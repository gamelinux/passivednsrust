use crate::capture::PacketObj;
use crate::dns_utils::{LogRecord, DnsFlow};
use crossbeam_channel::Receiver;
use etherparse::{PacketHeaders, IpHeader, TransportHeader, VlanHeader};
use dashmap::DashMap;
use std::time::{SystemTime, Duration};
use log::info;
use std::thread;
use std::net::{Ipv4Addr, Ipv6Addr};
use dns_parser::Name; 

type ContextMap = DashMap<String, (DnsFlow, SystemTime)>;

struct CacheState {
    record: LogRecord,
    last_seen: SystemTime,
    last_printed: SystemTime,
    printed_count: u64,
}

type OutputCache = DashMap<String, CacheState>;

pub fn run_parser(rx: Receiver<PacketObj>, cache_time: u64, print_time: u64, check_interval: u64) {
    let context: ContextMap = DashMap::new();
    let output_cache: std::sync::Arc<OutputCache> = std::sync::Arc::new(DashMap::new());

    let cache_ref = output_cache.clone();
    
    thread::spawn(move || {
        cleanup_loop(cache_ref, Duration::from_secs(cache_time), Duration::from_secs(print_time), Duration::from_secs(check_interval));
    });

    info!("Parser thread started (Cache: {}s, Print: {}s, Check: {}s)", cache_time, print_time, check_interval);

    while let Ok(pkt) = rx.recv() {
        parse_packet(&pkt, &context, &output_cache);
    }
}

fn to_iso(ts: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = ts.into();
    datetime.to_rfc3339()
}

fn cleanup_loop(cache: std::sync::Arc<OutputCache>, expiration: Duration, print_interval: Duration, check_interval: Duration) {
    loop {
        thread::sleep(check_interval);
        let mut keys_to_remove = Vec::new();
        let now = SystemTime::now();

        for mut r in cache.iter_mut() {
            let (key, state) = r.pair_mut();
            let age = now.duration_since(state.last_seen).unwrap_or(Duration::ZERO);
            if age > expiration {
                let delta = state.record.count - state.printed_count;
                if delta > 0 {
                    state.record.count = delta;
                    state.record.ts = chrono::Utc::now().to_rfc3339();
                    println!("{}", serde_json::to_string(&state.record).unwrap());
                }
                keys_to_remove.push(key.clone());
                continue;
            }

            let time_since_print = now.duration_since(state.last_printed).unwrap_or(Duration::ZERO);
            if time_since_print > print_interval {
                let delta = state.record.count - state.printed_count;
                if delta > 0 {
                    let mut print_rec = state.record.clone();
                    print_rec.count = delta;
                    print_rec.ts = chrono::Utc::now().to_rfc3339();
                    println!("{}", serde_json::to_string(&print_rec).unwrap());

                    state.printed_count = state.record.count;
                    state.last_printed = now;
                }
            }
        }

        for k in keys_to_remove {
            cache.remove(&k);
        }
    }
}

fn get_wire_name_len(data: &[u8], mut pos: usize) -> Option<usize> {
    let start = pos;
    loop {
        if pos >= data.len() { return None; }
        let b = data[pos];
        if b == 0 {
            return Some(pos - start + 1);
        } else if b & 0xC0 == 0xC0 {
            // Pointer (2 bytes total) ends the sequence in this frame
            if pos + 1 >= data.len() { return None; }
            return Some(pos - start + 2);
        } else {
            // Label
            let label_len = b as usize;
            pos += 1 + label_len;
        }
    }
}

fn parse_https_record(data: &[u8]) -> String {
    if data.len() < 2 { return String::new(); }
    let mut pos = 0;
    let read_u16 = |b: &[u8]| -> u16 { ((b[0] as u16) << 8) | (b[1] as u16) };

    // 1. Priority
    let priority = read_u16(&data[pos..pos+2]);
    pos += 2;

    // 2. Target Name (Uncompressed labels)
    let mut target_name = String::new();
    loop {
        if pos >= data.len() { break; }
        let len = data[pos] as usize;
        pos += 1;
        if len == 0 { break; }
        if pos + len > data.len() { return "Malformed".to_string(); }
        if !target_name.is_empty() { target_name.push('.'); }
        target_name.push_str(&String::from_utf8_lossy(&data[pos..pos+len]));
        pos += len;
    }
    if target_name.is_empty() { target_name = ".".to_string(); }

    let mut parts = Vec::new();
    parts.push(format!("{} {}", priority, target_name));

    // 3. Params
    while pos + 4 <= data.len() {
        let key = read_u16(&data[pos..pos+2]);
        pos += 2;
        let val_len = read_u16(&data[pos..pos+2]) as usize;
        pos += 2;
        if pos + val_len > data.len() { break; }
        let val = &data[pos..pos+val_len];
        pos += val_len;

        match key {
            1 => { // alpn
                let mut alpns = Vec::new();
                let mut p = 0;
                while p < val.len() {
                    let l = val[p] as usize;
                    p += 1;
                    if p + l > val.len() { break; }
                    alpns.push(String::from_utf8_lossy(&val[p..p+l]).to_string());
                    p += l;
                }
                parts.push(format!("alpn=\"{}\"", alpns.join(",")));
            },
            2 => parts.push("no-default-alpn".to_string()),
            3 => if val.len() == 2 { parts.push(format!("port={}", read_u16(val))); },
            4 => if val.len() % 4 == 0 {
                let mut ips = Vec::new();
                for chunk in val.chunks(4) {
                     ips.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]).to_string());
                }
                parts.push(format!("ipv4hint=\"{}\"", ips.join(",")));
            },
            6 => if val.len() % 16 == 0 {
                let mut ips = Vec::new();
                for chunk in val.chunks(16) {
                    let mut tmp = [0u8; 16];
                    tmp.copy_from_slice(chunk);
                    ips.push(Ipv6Addr::from(tmp).to_string());
                }
                parts.push(format!("ipv6hint=\"{}\"", ips.join(",")));
            },
            _ => {}
        }
    }
    parts.join(" ")
}

// --- MAIN PARSER FUNCTION ---
fn parse_packet(pkt: &PacketObj, ctx: &ContextMap, cache: &DashMap<String, CacheState>) {
    let headers = match PacketHeaders::from_ethernet_slice(&pkt.data) {
        Ok(h) => h,
        Err(_) => return, 
    };
    
    let vlan_id = match headers.vlan {
        Some(VlanHeader::Single(h)) => h.vlan_identifier,
        Some(VlanHeader::Double(h)) => h.outer.vlan_identifier,
        None => 0,
    };

    let (src_ip, dst_ip) = match headers.ip {
        Some(IpHeader::Version4(h, _)) => (h.source.map(|x| x.to_string()).join("."), h.destination.map(|x| x.to_string()).join(".")),
        Some(IpHeader::Version6(h, _)) => (h.source.map(|x| x.to_string()).join(":"), h.destination.map(|x| x.to_string()).join(":")),
        _ => return,
    };

    let (src_port, dst_port, proto) = match headers.transport {
        Some(TransportHeader::Udp(u)) => (u.source_port, u.destination_port, 17),
        Some(TransportHeader::Tcp(t)) => (t.source_port, t.destination_port, 6),
        _ => return, 
    };

    let payload = headers.payload;
    // Manual DNS Header check (12 bytes)
    if payload.len() < 12 { return; }

    // Helper to read u16
    let read_u16 = |pos: usize| -> u16 {
        ((payload[pos] as u16) << 8) | (payload[pos+1] as u16)
    };

    let tx_id = read_u16(0);
    let flags = read_u16(2);
    let qd_count = read_u16(4);
    let an_count = read_u16(6);

    let is_query = (flags & 0x8000) == 0; // QR bit is 0
    let rcode_val = flags & 0xF;

    let mut pos = 12; // Start after header

    if is_query {
        let key = format!("{}:{}:{}:{}", tx_id, proto, src_ip, src_port);
        let mut flow = DnsFlow {
            src_ip: src_ip.clone(), dst_ip: dst_ip, src_port: src_port as u16, dst_port: dst_port as u16, proto, vlan: vlan_id, tx_id,
            query_name: String::new(), query_type: String::new(),
        };

        // Parse first question for the key
        if qd_count > 0 {
            // Get wire length to skip later
            let name_len = get_wire_name_len(payload, pos).unwrap_or(0);
            if name_len > 0 {
                // Parse Name for the string (pass slice + full payload)
                if let Ok(name) = Name::scan(&payload[pos..], payload) {
                    flow.query_name = name.to_string();
                }
                pos += name_len;
                
                if pos + 4 <= payload.len() {
                    let qtype_u16 = read_u16(pos);
                    // pos += 2; // skip type
                    // pos += 2; // skip class
                    
                    if qtype_u16 == 65 {
                        flow.query_type = "HTTPS".to_string();
                    } else {
                        flow.query_type = format!("{:?}", dns_parser::QueryType::parse(qtype_u16).unwrap_or(dns_parser::QueryType::A));
                        if flow.query_type == "A" && qtype_u16 != 1 {
                             flow.query_type = format!("TYPE{}", qtype_u16);
                        }
                    }
                    ctx.insert(key, (flow, pkt.ts));
                }
            }
        }
    } else {
        // RESPONSE
        let key = format!("{}:{}:{}:{}", tx_id, proto, dst_ip, dst_port);
        
        // Remove `mut flow` -> just `flow`
        if let Some((_, (flow, start_ts))) = ctx.remove(&key) {
            let latency = pkt.ts.duration_since(start_ts).unwrap_or_default().as_secs_f64();
            
            // Skip Questions Section
            for _ in 0..qd_count {
                let len = match get_wire_name_len(payload, pos) {
                    Some(l) => l,
                    None => return, 
                };
                pos += len;
                if pos + 4 > payload.len() { return; }
                pos += 4; // Skip Type(2) + Class(2)
            }

            let mut answers: Vec<String> = Vec::new();
            let mut ttl_val = 0;

            for _ in 0..an_count {
                if pos >= payload.len() { break; }
                
                // 1. Parse Name (we don't strictly need the string here, just skip it, but let's be safe)
                let name_len = match get_wire_name_len(payload, pos) {
                    Some(l) => l,
                    None => break,
                };
                pos += name_len;

                if pos + 10 > payload.len() { break; }
                
                let atype = read_u16(pos);
                let attl = ((payload[pos+4] as u32) << 24) | ((payload[pos+5] as u32) << 16) | ((payload[pos+6] as u32) << 8) | (payload[pos+7] as u32);
                let rdlen = read_u16(pos+8) as usize;
                
                pos += 10; // Advance past record header

                if pos + rdlen > payload.len() { break; }
                let rdata = &payload[pos..pos+rdlen];

                if ttl_val == 0 { ttl_val = attl; }

                let ans_str = match atype {
                    1 => { // A
                        if rdata.len() == 4 {
                             Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()
                        } else { "Malformed IPv4".to_string() }
                    },
                    28 => { // AAAA
                        if rdata.len() == 16 {
                            let mut buf = [0u8; 16];
                            buf.copy_from_slice(rdata);
                            Ipv6Addr::from(buf).to_string()
                        } else { "Malformed IPv6".to_string() }
                    },
                    5 | 2 | 12 => { // CNAME, NS, PTR
                         // For these, RDATA contains a name. We must pass rdata as start, and full payload for pointers.
                         match Name::scan(rdata, payload) {
                             Ok(n) => n.to_string(),
                             Err(_) => "Bad Name".to_string(),
                         }
                    },
                    15 => { // MX
                        if rdata.len() > 2 {
                            let pref = read_u16(pos); // pos points to start of rdata in payload
                            // Name starts after 2 bytes of preference
                            match Name::scan(&payload[pos+2..], payload) {
                                Ok(n) => format!("{} {}", pref, n),
                                Err(_) => "Bad MX".to_string()
                            }
                        } else { "Bad MX".to_string() }
                    },
                    16 => { // TXT
                         String::from_utf8_lossy(rdata).to_string()
                    },
                    65 => { // HTTPS
                        parse_https_record(rdata)
                    },
                    _ => format!("TYPE{}[{}]", atype, rdlen)
                };
                
                answers.push(ans_str);
                pos += rdlen; // Advance past rdata
            }
            
            answers.sort();

            let rc_str = match rcode_val {
                0 => "NOERROR", 3 => "NXDOMAIN", 1 => "FORMERR", 2 => "SERVFAIL", 4 => "NOTIMP", 5 => "REFUSED", _ => "UNKNOWN"
            };

            let clean_atype = flow.query_type.clone();
            
            let record = LogRecord {
                query: flow.query_name.clone(),
                qtype: flow.query_type.clone(),
                answer: answers.clone(),
                atype: clean_atype.clone(),
                rc: rc_str.to_string(),
                ttl: ttl_val,
                src_ip: flow.src_ip.clone(),
                dst_ip: flow.dst_ip.clone(),
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                proto: flow.proto,
                vlan: flow.vlan,
                qid: flow.tx_id,
                latency,
                fts: to_iso(pkt.ts),
                lts: to_iso(pkt.ts),
                ts: chrono::Utc::now().to_rfc3339(),
                count: 1, 
            };

            let cache_key = if rc_str != "NOERROR" {
                 format!("{}:{}:{}", record.query, record.qtype, rc_str)
            } else {
                 let answer_key = answers.join(",");
                 format!("{}:{}:{}", record.query, clean_atype, answer_key)
            };

            if let Some(mut entry) = cache.get_mut(&cache_key) {
                let state = entry.value_mut();
                state.record.count += 1;
                state.record.lts = to_iso(pkt.ts);
                if record.ttl > state.record.ttl { state.record.ttl = record.ttl; }
                state.last_seen = SystemTime::now();
            } else {
                println!("{}", serde_json::to_string(&record).unwrap());
                cache.insert(cache_key, CacheState {
                    record,
                    last_seen: SystemTime::now(),
                    last_printed: SystemTime::now(),
                    printed_count: 1,
                });
            }
        }
    }
}
