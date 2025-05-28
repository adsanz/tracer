# Rust Traceroute Tool

A simple command-line traceroute utility written in Rust. This tool sends ICMP Echo Request packets with incrementally increasing TTL values to trace the path to a target host.

## Features

-   Traces routes to specified IP addresses (IPv4 only currently).
-   Configurable maximum number of hops (TTL).
-   Configurable timeout for each hop.
-   Optional reverse DNS lookup for hop IP addresses.
-   Continuous statistics mode (`--stats`) to monitor routes over time, displaying packet loss, average RTT, and other metrics.

## Prerequisites

-   Rust programming language and Cargo (Rust's package manager). Install from [rustup.rs](https://rustup.rs/).
-   Administrator/root privileges are required to run the tool, as it uses raw sockets.

## Building

1.  Clone the repository (if applicable) or navigate to the project directory.
2.  Build the project using Cargo:

    ```bash
    cargo build --release
    ```

    The executable will be located at `target/release/tracer`.

## Usage

Run the compiled executable with `sudo` (or as an administrator on Windows):

```bash
sudo ./target/release/tracer [OPTIONS] <TARGETS>...
```

### Arguments

-   `<TARGETS>...`: One or more target IP addresses to trace.

### Options

-   `-h, --help`: Print help information.
-   `-V, --version`: Print version information.
-   `-m, --max-hops <MAX_HOPS>`: Maximum number of hops (TTL).
    -   Default: `30`
-   `-t, --timeout-ms <TIMEOUT_MS>`: Timeout for each hop in milliseconds.
    -   Default: `1000`
-   `-r, --resolve`: Resolve IP addresses to hostnames.
-   `--stats`: Enable continuous statistics mode. In this mode, traces are run repeatedly until Ctrl+C is pressed. A summary of statistics is displayed upon termination.
-   `--stats-interval <STATS_INTERVAL>`: Interval in seconds between traces when in statistics mode.
    -   Default: `1`

## Examples

1.  Trace the route to `8.8.8.8`:

    ```bash
    sudo ./target/release/tracer 8.8.8.8
    ```

2.  Trace the route to `1.1.1.1` with a maximum of 20 hops and resolve hostnames:

    ```bash
    sudo ./target/release/tracer -m 20 -r 1.1.1.1
    ```

3.  Trace the route to multiple targets:

    ```bash
    sudo ./target/release/tracer 8.8.8.8 1.1.1.1
    ```

4.  Run traceroute in statistics mode for `8.8.8.8`, resolving hostnames, with a 5-second interval between traces:

    ```bash
    sudo ./target/release/tracer --stats --resolve --stats-interval 5 8.8.8.8
    ```

## How it Works

The tool sends ICMP Echo Request packets.
-   For each hop, it starts with a Time-To-Live (TTL) value of 1.
-   If a router along the path receives the packet and decrements TTL to 0, it sends back an ICMP "Time Exceeded" message. The source IP of this message is the router's IP.
-   If the packet reaches the destination host, the host sends back an ICMP "Echo Reply" message.
-   The TTL is incremented for each subsequent probe until the destination is reached or the maximum number of hops is exceeded.

## Dependencies

This project uses the following main Rust crates:
-   `clap` for command-line argument parsing.
-   `pnet` for low-level network packet manipulation.
-   `socket2` for enhanced socket control (raw sockets, TTL setting).
-   `anyhow` for error handling.
-   `dns-lookup` for reverse DNS lookups.
-   `comfy-table` for displaying statistics in a formatted table (in stats mode).
-   `ctrlc` for handling Ctrl+C interruption gracefully (in stats mode).
