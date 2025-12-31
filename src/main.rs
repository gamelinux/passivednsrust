mod capture;
mod parser;
mod dns_utils;

use clap::Parser;
use log::{info, error};
use std::thread;
use crossbeam_channel::bounded;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short, long, default_value = "any")]
    interface: String,

    #[arg(short, long, default_value = "udp and port 53")]
    bpf: String,

    #[arg(short, long, default_value_t = 1)]
    threads: usize,

    /// Time (seconds) before an idle flow is removed from cache
    #[arg(long, default_value_t = 21600)] 
    cache_time: u64,

    /// Time (seconds) to print an intermediate log for active flows
    #[arg(long, default_value_t = 43200)]
    print_time: u64,

    /// Interval (seconds) to scan the cache for expiration/printing
    #[arg(long, default_value_t = 60)]
    check_interval: u64,
}

fn main() {
    env_logger::init();
    let config = Config::parse();

    info!("Starting PassiveDNS Rust on interface: {}", config.interface);

    let running = Arc::new(AtomicBool::new(true));
    ctrlc::set_handler(move || {
        error!("Ctrl+C received! Forcing exit...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    let (packet_tx, packet_rx) = bounded(10_000);

    // Pass all timing configs to parser
    let parser_cache_time = config.cache_time;
    let parser_print_time = config.print_time;
    let parser_check_interval = config.check_interval;

    let parser_handle = thread::spawn(move || {
        parser::run_parser(packet_rx, parser_cache_time, parser_print_time, parser_check_interval);
    });

    let capture_config = config.clone();
    let capture_handle = thread::spawn(move || {
        if let Err(e) = capture::run_capture(capture_config.interface, capture_config.bpf, packet_tx, running) {
            error!("Capture failed: {}", e);
        }
    });

    let _ = capture_handle.join();
    let _ = parser_handle.join();
}
