use anyhow::{Context, Result, bail};
use clap::Parser;
use dns_lookup::lookup_addr;
// Cleaned up pnet imports
use comfy_table::{Cell, CellAlignment, Color, Row, Table};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{self as icmp_echo_request, MutableEchoRequestPacket};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::util;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::cmp::Ordering as CmpOrdering; // For sorting
use std::collections::HashMap;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr}; // Added Ipv4Addr
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant}; // Updated comfy-table imports

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about = "A simple traceroute tool to debug network connectivity."
)]
struct CliArgs {
    /// Target IP addresses to trace
    #[clap(required = true, num_args = 1..)]
    targets: Vec<IpAddr>,

    /// Maximum number of hops (TTL)
    #[clap(short, long, default_value_t = 30)]
    max_hops: u8,

    /// Timeout for each hop in milliseconds
    #[clap(short = 't', long, default_value_t = 1000)]
    timeout_ms: u64,

    /// Resolve IP addresses to hostnames
    #[clap(short, long)]
    resolve: bool,

    /// Enable continuous statistics mode
    #[clap(long)]
    stats: bool,

    /// Interval between traces in statistics mode (seconds)
    #[clap(long, default_value_t = 1)]
    stats_interval: u64,
}

// --- Data structures for statistics mode ---
#[derive(Debug, Default, Clone)]
struct HopStatistic {
    probes_sent: u64,
    responses_received: u64, // All non-timeout, non-operational-error replies
    timeouts: u64,
    destination_reached: u64,
    icmp_errors_received: u64, // Non-standard ICMP replies (e.g., not TE, ER, DU)
    operational_errors: u64,   // Send/Receive socket/parse errors
    responders: HashMap<IpAddr, u64>,
    total_rtt: Duration,
    rtt_count: u64, // Number of responses contributing to total_rtt
}

#[derive(Debug, Default)]
struct TargetStats {
    total_traces: u64,
    hop_stats: HashMap<u8, HopStatistic>, // Key is TTL
    last_route: Vec<Option<(IpAddr, Duration, HopResultType)>>, // (Responder IP, RTT, Result Type)
}

#[derive(Debug, Clone, PartialEq)]
enum HopResultType {
    Reply,         // Standard TimeExceeded
    TargetReached, // EchoReply from target
    Timeout,
    DestinationUnreachable,
    SpecificIcmpError {
        // Other ICMP messages
        icmp_type: pnet::packet::icmp::IcmpType,
        icmp_code: pnet::packet::icmp::IcmpCode,
    },
    OperationalError {
        message: String,
    }, // Tool/socket errors
}

#[derive(Debug, Clone)]
struct HopInfo {
    ttl: u8,
    result: HopResultInternal,
}

#[derive(Debug, Clone)]
enum HopResultInternal {
    Reply {
        ip: IpAddr,
        rtt: Duration,
    }, // TimeExceeded
    Timeout,
    DestinationUnreachable {
        ip: IpAddr,
        rtt: Duration,
    },
    TargetReached {
        ip: IpAddr,
        rtt: Duration,
    }, // EchoReply from target
    IcmpError {
        // Other ICMP types
        ip: IpAddr,
        rtt: Duration,
        icmp_type: pnet::packet::icmp::IcmpType,
        icmp_code: pnet::packet::icmp::IcmpCode,
    },
    SendError(String),
    ReceiveError(String),
}

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 16;

// Helper function to format IP or hostname
fn format_address(ip: IpAddr, resolve: bool) -> String {
    if ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
        return "".to_string(); // Handle unspecified IP gracefully
    }
    if resolve {
        match lookup_addr(&ip) {
            Ok(hostname) => format!("{} ({})", hostname, ip),
            Err(_) => ip.to_string(),
        }
    } else {
        ip.to_string()
    }
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    if args.stats {
        run_stats_mode(args)
    } else {
        run_single_trace_mode(args)
    }
}

fn run_single_trace_mode(args: CliArgs) -> Result<()> {
    println!("Starting tracer tool...");
    println!(
        "Targets: {:?}, Max Hops: {}, Timeout: {}ms, Resolve Hostnames: {}",
        args.targets, args.max_hops, args.timeout_ms, args.resolve
    );

    for target_ip in args.targets {
        println!("\nTracing route to {}:", target_ip);
        if let Err(e) = trace_route(
            target_ip,
            args.max_hops,
            Duration::from_millis(args.timeout_ms),
            args.resolve,
        ) {
            eprintln!("Error tracing {}: {:?}", target_ip, e);
        }
    }
    Ok(())
}

fn run_stats_mode(args: CliArgs) -> Result<()> {
    println!(
        "Starting statistics mode for targets: {:?}...",
        args.targets
    );
    println!(
        "Max Hops: {}, Timeout: {}ms, Resolve Hostnames: {}, Interval: {}s",
        args.max_hops, args.timeout_ms, args.resolve, args.stats_interval
    );
    println!("Press Ctrl+C to stop.");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut all_target_stats: HashMap<IpAddr, TargetStats> = HashMap::new();
    for target_ip in &args.targets {
        all_target_stats.insert(*target_ip, TargetStats::default());
    }

    let mut iteration_count = 0;

    while running.load(Ordering::SeqCst) {
        iteration_count += 1;
        for target_ip in &args.targets {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            let current_target_stats = all_target_stats.get_mut(target_ip).unwrap();
            current_target_stats.total_traces += 1;

            let hop_infos = trace_route_for_stats(
                *target_ip,
                args.max_hops,
                Duration::from_millis(args.timeout_ms),
                Arc::clone(&running),
            )?;

            update_target_stats(current_target_stats, &hop_infos, args.max_hops);
            
            print!(".");
            std::io::stdout().flush().context("Failed to flush stdout for dot")?;
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }

        if running.load(Ordering::SeqCst) {
            // Check again before sleep
            std::thread::sleep(Duration::from_secs(args.stats_interval));
        }
    }

    println!(); // Newline after all the dots
    println!("\\nCtrl+C received, shutting down...");
    println!("--- Final Statistics ({} iterations) ---", iteration_count);
    display_all_stats(&all_target_stats, &args)?; 
    Ok(())
}

fn trace_route_for_stats(
    target_ip: IpAddr,
    max_hops: u8,
    timeout: Duration,
    running: Arc<AtomicBool>,
) -> Result<Vec<HopInfo>> {
    let target_ipv4 = match target_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => bail!("IPv6 targets are not supported in this version."),
    };

    let trace_identifier = (std::process::id() % (u16::MAX as u32)) as u16;
    let mut results = Vec::new();

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("Failed to create raw socket. Check permissions (sudo/admin).")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout on socket")?;

    for ttl in 1..=max_hops {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        socket
            .set_ttl(ttl as u32)
            .context(format!("Failed to set TTL to {}", ttl))?;

        let mut icmp_buf = vec![0u8; ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE];
        let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buf)
            .context("Failed to create mutable ICMP packet wrapper")?;
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(icmp_echo_request::IcmpCodes::NoCode);

        let mut echo_request_packet = MutableEchoRequestPacket::new(icmp_packet.packet_mut())
            .context("Failed to create mutable echo request packet")?;
        echo_request_packet.set_identifier(trace_identifier);
        echo_request_packet.set_sequence_number(ttl as u16);

        let payload_bytes = (ttl as u32).to_be_bytes();
        let current_payload_size = std::cmp::min(ICMP_PAYLOAD_SIZE, payload_bytes.len());
        echo_request_packet.payload_mut()[..current_payload_size]
            .copy_from_slice(&payload_bytes[..current_payload_size]);

        let checksum = util::checksum(echo_request_packet.packet(), 1);
        let mut icmp_packet_for_checksum = MutableIcmpPacket::new(echo_request_packet.packet_mut())
            .context("Failed to re-wrap for checksum")?;
        icmp_packet_for_checksum.set_checksum(checksum);

        let dest = SocketAddr::new(IpAddr::V4(target_ipv4), 0);
        let sock_addr_dest = SockAddr::from(dest);

        let send_time = Instant::now();
        if let Err(e) = socket.send_to(icmp_packet_for_checksum.packet(), &sock_addr_dest) {
            results.push(HopInfo {
                ttl,
                result: HopResultInternal::SendError(e.to_string()),
            });
            continue;
        }

        let mut recv_buf_uninit = [MaybeUninit::uninit(); 2048];
        match socket.recv_from(&mut recv_buf_uninit) {
            Ok((bytes_read, responder_sockaddr)) => {
                let rtt = send_time.elapsed();
                let responder_ip = responder_sockaddr
                    .as_socket()
                    .context("Failed to get socket address from responder")?
                    .ip();
                let recv_buf_initialized: &[u8] = unsafe {
                    std::slice::from_raw_parts(recv_buf_uninit.as_ptr() as *const u8, bytes_read)
                };

                let hop_result_internal =
                    if let Some(ipv4_packet) = Ipv4Packet::new(recv_buf_initialized) {
                        if let Some(received_icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                            match received_icmp_packet.get_icmp_type() {
                                IcmpTypes::TimeExceeded => HopResultInternal::Reply {
                                    ip: responder_ip,
                                    rtt,
                                },
                                IcmpTypes::EchoReply => {
                                    if let Some(echo_reply_packet) =
                                        EchoReplyPacket::new(received_icmp_packet.packet())
                                    {
                                        if echo_reply_packet.get_identifier() == trace_identifier
                                            && echo_reply_packet.get_sequence_number() == ttl as u16
                                        {
                                            if responder_ip == IpAddr::V4(target_ipv4) {
                                                HopResultInternal::TargetReached {
                                                    ip: responder_ip,
                                                    rtt,
                                                }
                                            } else {
                                                // EchoReply from intermediate hop (less common, but possible)
                                                HopResultInternal::Reply {
                                                    ip: responder_ip,
                                                    rtt,
                                                }
                                            }
                                        } else {
                                            // Mismatched EchoReply, treat as a generic ICMP for stats
                                            HopResultInternal::IcmpError {
                                                ip: responder_ip,
                                                rtt,
                                                icmp_type: received_icmp_packet.get_icmp_type(),
                                                icmp_code: received_icmp_packet.get_icmp_code(),
                                            }
                                        }
                                    } else {
                                        // Malformed EchoReply
                                        HopResultInternal::IcmpError {
                                            ip: responder_ip,
                                            rtt,
                                            icmp_type: IcmpTypes::EchoReply,
                                            icmp_code: received_icmp_packet.get_icmp_code(),
                                        }
                                    }
                                }
                                IcmpTypes::DestinationUnreachable => {
                                    HopResultInternal::DestinationUnreachable {
                                        ip: responder_ip,
                                        rtt,
                                    }
                                }
                                other_type => HopResultInternal::IcmpError {
                                    ip: responder_ip,
                                    rtt,
                                    icmp_type: other_type,
                                    icmp_code: received_icmp_packet.get_icmp_code(),
                                },
                            }
                        } else {
                            HopResultInternal::ReceiveError(format!(
                                "Failed to parse ICMP packet from {}",
                                responder_ip
                            ))
                        }
                    } else {
                        HopResultInternal::ReceiveError(format!(
                            "Received non-IPv4 packet from {}",
                            responder_ip
                        ))
                    };
                results.push(HopInfo {
                    ttl,
                    result: hop_result_internal.clone(),
                });
                if matches!(
                    hop_result_internal,
                    HopResultInternal::TargetReached { .. }
                        | HopResultInternal::DestinationUnreachable { .. }
                ) {
                    break;
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    results.push(HopInfo {
                        ttl,
                        result: HopResultInternal::Timeout,
                    });
                } else {
                    results.push(HopInfo {
                        ttl,
                        result: HopResultInternal::ReceiveError(e.to_string()),
                    });
                }
            }
        }
        if running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50)); // Small delay between probes within a trace
        }
    }
    Ok(results)
}

fn update_target_stats(stats: &mut TargetStats, hop_infos: &[HopInfo], max_hops: u8) {
    stats.last_route = vec![None; max_hops as usize];

    for info in hop_infos {
        let hop_stat = stats
            .hop_stats
            .entry(info.ttl)
            .or_default();
        hop_stat.probes_sent += 1;
        let route_idx = (info.ttl - 1) as usize;

        let (responder_ip_opt, rtt_opt, result_type_for_route) = match &info.result {
            HopResultInternal::Reply { ip, rtt } => {
                hop_stat.responses_received += 1;
                hop_stat.total_rtt += *rtt;
                hop_stat.rtt_count += 1;
                *hop_stat.responders.entry(*ip).or_insert(0) += 1;
                (Some(*ip), Some(*rtt), HopResultType::Reply)
            }
            HopResultInternal::TargetReached { ip, rtt } => {
                hop_stat.responses_received += 1;
                hop_stat.destination_reached += 1;
                hop_stat.total_rtt += *rtt;
                hop_stat.rtt_count += 1;
                *hop_stat.responders.entry(*ip).or_insert(0) += 1;
                (Some(*ip), Some(*rtt), HopResultType::TargetReached)
            }
            HopResultInternal::DestinationUnreachable { ip, rtt } => {
                hop_stat.responses_received += 1;
                // Consider if DU should count towards avg RTT. Usually they are fast.
                hop_stat.total_rtt += *rtt;
                hop_stat.rtt_count += 1;
                *hop_stat.responders.entry(*ip).or_insert(0) += 1;
                (Some(*ip), Some(*rtt), HopResultType::DestinationUnreachable)
            }
            HopResultInternal::IcmpError {
                ip,
                rtt,
                icmp_type,
                icmp_code,
            } => {
                hop_stat.icmp_errors_received += 1;
                hop_stat.responses_received += 1; // It's a response, albeit an error one
                hop_stat.total_rtt += *rtt;
                hop_stat.rtt_count += 1;
                *hop_stat.responders.entry(*ip).or_insert(0) += 1;
                (
                    Some(*ip),
                    Some(*rtt),
                    HopResultType::SpecificIcmpError {
                        icmp_type: *icmp_type,
                        icmp_code: *icmp_code,
                    },
                )
            }
            HopResultInternal::Timeout => {
                hop_stat.timeouts += 1;
                (
                    Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    Some(Duration::ZERO),
                    HopResultType::Timeout,
                )
            }
            HopResultInternal::SendError(s) | HopResultInternal::ReceiveError(s) => {
                hop_stat.operational_errors += 1;
                (
                    Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    Some(Duration::ZERO),
                    HopResultType::OperationalError { message: s.clone() },
                )
            }
        };

        if route_idx < stats.last_route.len() {
            if let (Some(ip), Some(rtt)) = (responder_ip_opt, rtt_opt) {
                stats.last_route[route_idx] = Some((ip, rtt, result_type_for_route));
            }
        }
    }
}

fn display_all_stats(
    all_target_stats: &HashMap<IpAddr, TargetStats>,
    args: &CliArgs,
) -> Result<()> {
    print!("\\x1B[2J\\x1B[1;1H"); // Clear screen and move cursor to top-left

    println!(
        "Max Hops: {}, Timeout: {}ms, Resolve: {}",
        args.max_hops, args.timeout_ms, args.resolve
    );
    println!("{:-<80}", "");

    for (target_ip, stats) in all_target_stats {
        println!(
            "Target: {} (Total Traces: {})",
            format_address(*target_ip, args.resolve),
            stats.total_traces
        );
        println!("Last Route:");
        let mut route_display_complete = false;
        for ttl_idx in 0..args.max_hops as usize {
            let ttl = (ttl_idx + 1) as u8;
            match stats.last_route.get(ttl_idx).and_then(|opt| opt.as_ref()) {
                Some((ip, rtt, result_type)) => {
                    let address_str = format_address(*ip, args.resolve);
                    let rtt_str =
                        if *result_type != HopResultType::Timeout && *rtt != Duration::ZERO {
                            format!(" ({:.2?})", rtt)
                        } else {
                            "".to_string()
                        };

                    let type_str = match result_type {
                        HopResultType::Reply => "".to_string(),
                        HopResultType::TargetReached => " (Target Reached)".to_string(),
                        HopResultType::Timeout => "* * * (Timeout)".to_string(),
                        HopResultType::DestinationUnreachable => {
                            " (Destination Unreachable)".to_string()
                        }
                        HopResultType::SpecificIcmpError {
                            icmp_type,
                            icmp_code,
                        } => {
                            format!(" (ICMP Error: Type {:?}, Code {:?})", icmp_type, icmp_code)
                        }
                        HopResultType::OperationalError { message } => {
                            format!(" (Error: {})", message)
                        }
                    };

                    if *result_type == HopResultType::Timeout {
                        println!("  {:>2}: {}", ttl, type_str);
                    } else {
                        println!("  {:>2}: {}{}{}", ttl, address_str, rtt_str, type_str);
                    }

                    if matches!(
                        result_type,
                        HopResultType::TargetReached | HopResultType::DestinationUnreachable
                    ) {
                        route_display_complete = true;
                        break;
                    }
                }
                None => {
                    // Hop not reached or no data for this TTL in last trace
                    if stats.hop_stats.get(&ttl).map_or(false, |hs| {
                        hs.probes_sent > 0
                            && hs.timeouts == hs.probes_sent
                            && hs.responses_received == 0
                    }) {
                        println!("  {:>2}: * * * (Timeout)", ttl);
                    } else if route_display_complete {
                        break; // Stop if route was already completed by an earlier hop
                    }
                }
            }
        }
        if !route_display_complete
            && stats.total_traces > 0
            && !stats.last_route.is_empty()
            && stats.last_route.iter().flatten().count() == args.max_hops as usize
            && !matches!(
                stats.last_route.last().unwrap().as_ref().unwrap().2,
                HopResultType::TargetReached
            )
        {
            println!("      (Trace reached max hops without reaching target)");
        }
        println!();

        let mut table = Table::new();
        table.set_header(Row::from(vec![
            Cell::new("TTL").set_alignment(CellAlignment::Center),
            Cell::new("Sent").set_alignment(CellAlignment::Center),
            Cell::new("Recv").set_alignment(CellAlignment::Center),
            Cell::new("Timeouts").set_alignment(CellAlignment::Center),
            Cell::new("ICMPErr").set_alignment(CellAlignment::Center),
            Cell::new("OpErr").set_alignment(CellAlignment::Center),
            Cell::new("Avg RTT").set_alignment(CellAlignment::Center),
            Cell::new("Loss %").set_alignment(CellAlignment::Center),
            Cell::new("Responders").set_alignment(CellAlignment::Left),
        ]));

        let mut hop_stats_to_display: Vec<_> = stats.hop_stats.iter().collect();

        // Sorting is now unconditionally by loss percentage for the final summary
        hop_stats_to_display.sort_by(|(_, a_stat), (_, b_stat)| {
            let loss_a = if a_stat.probes_sent == 0 {
                0.0
            } else {
                a_stat.timeouts as f64 / a_stat.probes_sent as f64
            };
            let loss_b = if b_stat.probes_sent == 0 {
                0.0
            } else {
                b_stat.timeouts as f64 / b_stat.probes_sent as f64
            };
            loss_b.partial_cmp(&loss_a).unwrap_or(CmpOrdering::Equal)
        });
        // Removed the 'else' branch for sorting by TTL and the 'is_final_summary' check

        let mut stats_display_complete_for_target = false; // This logic might need review if it depended on non-final display
        for (ttl, hop_stat) in hop_stats_to_display {
            if hop_stat.probes_sent == 0 {
                // if stats_display_complete_for_target && !is_final_summary { // is_final_summary removed
                if stats_display_complete_for_target { // Simplified: if already complete, and this hop has no data, skip.
                     // This logic was to stop printing TTLs beyond the target in non-final.
                     // For final, we usually show all collected stats.
                     // Let's reconsider this break condition. For final summary, we want all data.
                }
                // Let's remove the conditional break here for the final summary,
                // as we want to show all hops that have data.
                // The original `if stats_display_complete_for_target && !is_final_summary { break; }`
                // was for not showing empty TTL rows past the target in *intermediate* displays.
                // For the final display, it's fine to show all collected data.
                // So, if probes_sent is 0, we just continue.
                continue;
            }

            let loss_percentage = if hop_stat.probes_sent > 0 {
                (hop_stat.timeouts as f64 / hop_stat.probes_sent as f64) * 100.0
            } else {
                0.0
            };

            let avg_rtt_str = if hop_stat.rtt_count > 0 {
                format!("{:.2?}", hop_stat.total_rtt / hop_stat.rtt_count as u32)
            } else {
                "-".to_string()
            };

            let mut responder_str_parts = Vec::new();
            if args.resolve
                || hop_stat.responders.len() > 1
                || hop_stat
                    .responders
                    .iter()
                    .any(|(ip, _)| *ip != *target_ip && *ip != IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            {
                for (ip, count) in &hop_stat.responders {
                    if *ip != IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                        responder_str_parts.push(format!(
                            "{}: {}",
                            format_address(*ip, args.resolve),
                            count
                        ));
                    }
                }
            }
            let responder_display = responder_str_parts.join("\n"); // This is the key line for formatting

            let loss_cell =
                Cell::new(format!("{:.1}%", loss_percentage)).set_alignment(CellAlignment::Right);

            let loss_cell_colored = if loss_percentage > 10.0 && loss_percentage < 50.0 {
                loss_cell.fg(Color::Yellow)
            } else if loss_percentage >= 50.0 {
                loss_cell.fg(Color::Red)
            } else {
                loss_cell
            };

            table.add_row(Row::from(vec![
                Cell::new(ttl.to_string()).set_alignment(CellAlignment::Center),
                Cell::new(hop_stat.probes_sent.to_string()).set_alignment(CellAlignment::Center),
                Cell::new(hop_stat.responses_received.to_string())
                    .set_alignment(CellAlignment::Center),
                Cell::new(hop_stat.timeouts.to_string()).set_alignment(CellAlignment::Center),
                Cell::new(hop_stat.icmp_errors_received.to_string())
                    .set_alignment(CellAlignment::Center),
                Cell::new(hop_stat.operational_errors.to_string())
                    .set_alignment(CellAlignment::Center),
                Cell::new(avg_rtt_str).set_alignment(CellAlignment::Right),
                loss_cell_colored,
                Cell::new(responder_display).set_alignment(CellAlignment::Left),
            ]));

            if hop_stat.destination_reached > 0
                && hop_stat.destination_reached
                    == hop_stat.probes_sent - hop_stat.timeouts - hop_stat.operational_errors
            {
                stats_display_complete_for_target = true; 
                // This flag helped stop printing further empty TTLs in intermediate views.
                // In a final summary, it's less critical for breaking the loop, but can be kept.
            }
        }
        println!("{}", table);
        println!("{:-<80}", "");
    }
    std::io::stdout().flush().context("Failed to flush stdout in display_all_stats")?;
    Ok(())
}

// Original trace_route function for single trace mode (remains largely unchanged)
fn trace_route(target_ip: IpAddr, max_hops: u8, timeout: Duration, resolve: bool) -> Result<()> {
    let target_ipv4 = match target_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            bail!("IPv6 targets are not supported in this version.");
        }
    };

    let trace_identifier = (std::process::id() % (u16::MAX as u32)) as u16;

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).context(
        "Failed to create raw socket. Check socket2 version and permissions (sudo/admin).",
    )?;
    socket
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout on socket")?;

    println!(
        "Tracing route to {} ({}) with max {} hops:",
        format_address(target_ip, resolve),
        target_ip,
        max_hops
    );

    for ttl in 1..=max_hops {
        socket
            .set_ttl(ttl as u32)
            .context(format!("Failed to set TTL to {}", ttl))?;

        let mut icmp_buf = vec![0u8; ICMP_HEADER_SIZE + ICMP_PAYLOAD_SIZE];
        let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buf)
            .context("Failed to create mutable ICMP packet wrapper")?;
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(icmp_echo_request::IcmpCodes::NoCode);

        let mut echo_request_packet = MutableEchoRequestPacket::new(icmp_packet.packet_mut())
            .context("Failed to create mutable echo request packet")?;

        echo_request_packet.set_identifier(trace_identifier);
        echo_request_packet.set_sequence_number(ttl as u16);

        let payload_bytes = (ttl as u32).to_be_bytes();
        let current_payload_size = std::cmp::min(ICMP_PAYLOAD_SIZE, payload_bytes.len());
        echo_request_packet.payload_mut()[..current_payload_size]
            .copy_from_slice(&payload_bytes[..current_payload_size]);

        let checksum = util::checksum(echo_request_packet.packet(), 1);
        let mut icmp_packet_for_checksum = MutableIcmpPacket::new(echo_request_packet.packet_mut())
            .context("Failed to re-wrap for checksum")?;
        icmp_packet_for_checksum.set_checksum(checksum);

        let dest = SocketAddr::new(IpAddr::V4(target_ipv4), 0);
        let sock_addr_dest = SockAddr::from(dest);

        let send_time = Instant::now();
        socket
            .send_to(icmp_packet_for_checksum.packet(), &sock_addr_dest)
            .context(format!("Failed to send ICMP packet with TTL {}", ttl))?;

        let mut recv_buf_uninit = [MaybeUninit::uninit(); 2048];

        print!(" {:<2} ", ttl);

        match socket.recv_from(&mut recv_buf_uninit) {
            Ok((bytes_read, responder_sockaddr)) => {
                let rtt = send_time.elapsed();
                let responder_ip = responder_sockaddr
                    .as_socket()
                    .context("Failed to get socket address from responder")?
                    .ip();
                let display_address = format_address(responder_ip, resolve);

                let recv_buf_initialized: &[u8] = unsafe {
                    std::slice::from_raw_parts(recv_buf_uninit.as_ptr() as *const u8, bytes_read)
                };

                if let Some(ipv4_packet) = Ipv4Packet::new(recv_buf_initialized) {
                    if let Some(received_icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                        match received_icmp_packet.get_icmp_type() {
                            IcmpTypes::TimeExceeded => {
                                println!("{}  {:.2?}", display_address, rtt);
                                if let Some(time_exceeded_packet) =
                                    TimeExceededPacket::new(received_icmp_packet.payload())
                                {
                                    if let Some(inner_ipv4_packet) =
                                        Ipv4Packet::new(time_exceeded_packet.payload())
                                    {
                                        if let Some(original_icmp_echo_packet) =
                                            pnet::packet::icmp::echo_request::EchoRequestPacket::new(
                                                inner_ipv4_packet.payload(),
                                            )
                                        {
                                            if !(original_icmp_echo_packet.get_identifier()
                                                == trace_identifier
                                                && original_icmp_echo_packet.get_sequence_number()
                                                    == ttl as u16)
                                            {
                                                // eprint!("[Note: Inner packet ID/Seq mismatch for TTL {} from {}] ", ttl, responder_ip);
                                            }
                                        }
                                    }
                                }
                            }
                            IcmpTypes::EchoReply => {
                                if let Some(echo_reply_packet) =
                                    EchoReplyPacket::new(received_icmp_packet.packet())
                                {
                                    let id_match =
                                        echo_reply_packet.get_identifier() == trace_identifier;
                                    let seq_match =
                                        echo_reply_packet.get_sequence_number() == ttl as u16;

                                    if responder_ip == IpAddr::V4(target_ipv4) {
                                        if id_match && seq_match {
                                            println!("{}  {:.2?}", display_address, rtt);
                                        } else {
                                            println!(
                                                "{}  {:.2?} (ID/Seq mismatch)",
                                                display_address, rtt
                                            );
                                        }
                                        println!(
                                            "Trace complete to {}.",
                                            format_address(target_ip, resolve)
                                        );
                                        return Ok(());
                                    } else if id_match && seq_match {
                                        println!(
                                            "{}  {:.2?}{}",
                                            display_address,
                                            rtt,
                                            if responder_ip == IpAddr::V4(target_ipv4) {
                                                ""
                                            } else {
                                                " (Intermediate EchoReply)"
                                            }
                                        );
                                    } else {
                                        println!(
                                            "{} (mismatched EchoReply id/seq from intermediate) {:.2?}",
                                            display_address, rtt
                                        );
                                    }
                                } else {
                                    println!(
                                        "{} (malformed EchoReply) {:.2?}",
                                        display_address, rtt
                                    );
                                }
                            }
                            IcmpTypes::DestinationUnreachable => {
                                println!(
                                    "{}  Destination Unreachable ({:?})  {:.2?}",
                                    display_address,
                                    received_icmp_packet.get_icmp_code(),
                                    rtt
                                );
                                println!(
                                    "Trace aborted to {}.",
                                    format_address(target_ip, resolve)
                                );
                                return Ok(());
                            }
                            other_type => {
                                println!(
                                    "{}  Received ICMP Type: {:?} Code: {:?}  {:.2?}",
                                    display_address,
                                    other_type,
                                    received_icmp_packet.get_icmp_code(),
                                    rtt
                                );
                            }
                        }
                    } else {
                        println!(
                            "Failed to parse ICMP packet from {}",
                            format_address(responder_ip, resolve)
                        );
                    }
                } else {
                    println!(
                        "Received non-IPv4 packet from {}",
                        format_address(responder_ip, resolve)
                    );
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    println!("* * * (Timeout)");
                } else {
                    println!("Error receiving packet: {:?}", e);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    println!(
        "Trace to {} finished (max hops {} reached).",
        format_address(target_ip, resolve),
        max_hops
    );
    Ok(())
}
