# PassiveDNS Rust

A high-performance, multithreaded DNS sniffer written in Rust, focusing on memory safety and zero-GC latency.

## Features
* **Fast**: Uses `libpcap` for packet capture.
* **Safe**: Written in 100% safe Rust (no `unsafe` blocks in application logic).
* **Compatible**: Outputs JSON logs schema-compatible with the passivednsgo version.
* **Tunable**: Configurable cache eviction, heartbeat printing, and garbage collection intervals.

## Limitations
* **TCP**: No TCP Reassembly. It processes packets individually. If a DNS response over TCP is fragmented or split across packets, this tool will not parse it.
* **Fanout**: Uses a single capture handle. It does not utilize kernel-level `AF_PACKET` fanout groups, so capture throughput is limited to a single CPU core.

## Usage

```bash
# Build
cargo build --release

# Run (requires root or CAP_NET_RAW)
sudo ./target/release/passivednsrust --interface eth0

```

### Configuration Options

You can tune the caching and printing behavior to match your traffic load:

```bash
sudo ./target/release/passivednsrust \
  --interface eth0 \
  --threads 1 \
  --cache-time 21600 \    # Evict flows after 6 hours of inactivity
  --print-time 43200 \    # Print "heartbeat" logs for active flows every 12 hours
  --check-interval 60     # Run the cleanup/expiration scan every 60 seconds

```

## License

MIT
