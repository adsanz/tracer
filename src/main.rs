use anyhow::{Context, Result, bail};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use clap::Parser;
// Cleaned up pnet imports
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{
    self as icmp_echo_request, EchoRequestPacket, MutableEchoRequestPacket,
};
use pnet::packet::icmp::time_exceeded::TimeExceededPacket; // Will be used now
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::util;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
// Import for DNS lookup
use dns_lookup::lookup_addr;

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
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

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

const ICMP_HEADER_SIZE: usize = 8;
const ICMP_PAYLOAD_SIZE: usize = 16;

// Helper function to format IP or hostname
fn format_address(ip: IpAddr, resolve: bool) -> String {
    if resolve {
        // This 'resolve' is the flag from command line args
        match lookup_addr(&ip) {
            // Attempts DNS lookup for the given IP
            Ok(hostname) => format!("{} ({})", hostname, ip),
            Err(_) => ip.to_string(), // If lookup fails, fallback to IP string
        }
    } else {
        ip.to_string()
    }
}

fn trace_route(target_ip: IpAddr, max_hops: u8, timeout: Duration, resolve: bool) -> Result<()> {
    let target_ipv4 = match target_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            bail!("IPv6 targets are not supported in this version.");
        }
    };

    let trace_identifier = std::process::id() as u16;

    // With socket2 = { version = "0.5.5", features = ["all"] } in Cargo.toml,
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).context(
        "Failed to create raw socket. Check socket2 version and permissions (sudo/admin).",
    )?;
    socket
        .set_read_timeout(Some(timeout))
        .context("Failed to set read timeout on socket")?;

    println!(
        "Tracing route to {} ({}) with max {} hops:",
        format_address(target_ip, resolve), // Resolve target IP for initial message
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
                                // Print the router IP and RTT consistently for visual appeal.
                                println!("{}  {:.2?}", display_address, rtt);

                                // The following is for internal validation/debugging if needed.
                                // It does not affect the primary stdout format anymore.
                                if let Some(time_exceeded_packet) =
                                    TimeExceededPacket::new(received_icmp_packet.payload())
                                {
                                    if let Some(inner_ipv4_packet) =
                                        Ipv4Packet::new(time_exceeded_packet.payload())
                                    {
                                        if let Some(original_icmp_echo_packet) =
                                            EchoRequestPacket::new(inner_ipv4_packet.payload())
                                        {
                                            if !(original_icmp_echo_packet.get_identifier()
                                                == trace_identifier
                                                && original_icmp_echo_packet.get_sequence_number()
                                                    == ttl as u16)
                                            {
                                                // Example for debug: eprint!("[Note: Inner packet ID/Seq mismatch for TTL {} from {}] ", ttl, responder_ip);
                                            }
                                        } // else { eprint!("[Note: Could not parse inner packet as EchoRequest for TTL {} from {}] ", ttl, responder_ip); }
                                    } // else { eprint!("[Note: Could not parse inner IPv4 packet for TTL {} from {}] ", ttl, responder_ip); }
                                } // else { eprint!("[Note: Could not parse TimeExceeded packet structure for TTL {} from {}] ", ttl, responder_ip); }
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
                                        println!("{}  {:.2?}", display_address, rtt);
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
                                    "{}  Destination Unreachable  {:.2?}",
                                    display_address, rtt
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
