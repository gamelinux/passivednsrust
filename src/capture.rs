use pcap::{Capture, Device};
use crossbeam_channel::Sender;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use log::info;

#[derive(Debug)]
pub struct PacketObj {
    pub ts: SystemTime,
    pub data: Vec<u8>,
}

pub fn run_capture(
    interface: String,
    bpf: String,
    tx: Sender<PacketObj>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    
    let device = if interface == "any" {
        Device::lookup()?.unwrap() 
    } else {
        Device::from(interface.as_str())
    };

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535) 
        .timeout(100) 
        .open()?;

    cap.filter(&bpf, true)?;

    info!("Capture loop started.");

    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let obj = PacketObj {
                    ts: SystemTime::now(),
                    data: packet.data.to_vec(),
                };
                if tx.send(obj).is_err() {
                    break;
                }
            },
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => eprintln!("PCAP Error: {}", e),
        }
    }
    
    info!("Capture loop stopping...");
    Ok(())
}
