use crate::capture::PacketObj;
use crate::dns_utils::{LogRecord, DnsFlow};
use crate::reasm::{L4Msg, Reassembler};
use crossbeam_channel::Receiver;
use dashmap::DashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, Duration};
use log::info;
use std::thread;
use std::net::{Ipv4Addr, Ipv6Addr};
use dns_parser::Name;

/// JSON log destination. Omit the path, or pass "-", to keep stdout.
#[derive(Clone)]
pub struct LogOut {
    inner: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl LogOut {
    pub fn stdout() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Box::new(io::stdout()))),
        }
    }

    /// Create or append. Each line is flushed so a copytruncate still sees it.
    pub fn open(path: &str) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o644);
        }
        let file = opts.open(path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Box::new(file))),
        })
    }

    fn write_line(&self, line: &str) {
        let mut w = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if writeln!(w, "{line}").is_err() || w.flush().is_err() {
            eprintln!("[!] failed to write log line");
        }
    }
} 

type ContextMap = DashMap<String, (DnsFlow, SystemTime)>;

struct CacheState {
    record: LogRecord,
    last_seen: SystemTime,
    last_printed: SystemTime,
    printed_count: u64,
}

type OutputCache = DashMap<String, CacheState>;

pub fn run_parser(rx: Receiver<PacketObj>, log: LogOut, cache_time: u64, print_time: u64, check_interval: u64) {
    let context: ContextMap = DashMap::new();
    let output_cache: std::sync::Arc<OutputCache> = std::sync::Arc::new(DashMap::new());

    let cache_ref = output_cache.clone();
    let cache_log = log.clone();
    
    thread::spawn(move || {
        cleanup_loop(cache_log, cache_ref, Duration::from_secs(cache_time), Duration::from_secs(print_time), Duration::from_secs(check_interval));
    });

    info!("Parser thread started (Cache: {}s, Print: {}s, Check: {}s)", cache_time, print_time, check_interval);

    let mut reasm = Reassembler::new();
    while let Ok(pkt) = rx.recv() {
        parse_packet(&pkt, &mut reasm, &context, &output_cache, &log);
    }
    // Write each cache entry's pending sightings. cnt is that
    // unwritten count. An entry already fully logged is skipped.
    flush_output_cache(&log, &output_cache);
}

fn flush_output_cache(log: &LogOut, cache: &OutputCache) {
    for mut entry in cache.iter_mut() {
        let state = entry.value_mut();
        if state.record.count <= state.printed_count {
            continue;
        }
        let mut print_rec = state.record.clone();
        print_rec.count = state.record.count - state.printed_count;
        print_rec.ts = now_iso();
        state.printed_count = state.record.count;
        state.last_printed = SystemTime::now();
        emit(log, &print_rec);
    }
}

fn emit(log: &LogOut, record: &LogRecord) {
    let s = serde_json::to_string(record).unwrap_or_default();
    let line = if let Some(i) = s.rfind("\"qtm\":") {
        format!("{}\"qtm\":{:.6}}}", &s[..i], record.latency)
    } else {
        s
    };
    log.write_line(&line);
}

fn to_iso(ts: SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = ts.into();
    datetime.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn strip_dot(s: String) -> String {
    if s.len() > 1 && s.ends_with('.') {
        let mut t = s;
        t.pop();
        t
    } else {
        s
    }
}

fn type_name(code: u16) -> String {
    let name = match code {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        39 => "DNAME",
        43 => "DS",
        44 => "SSHFP",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        255 => "ANY",
        257 => "CAA",
        _ => return format!("TYPE{}", code),
    };
    name.to_string()
}

fn rcode_name(code: u16) -> String {
    match code {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        6 => "YXDOMAIN".to_string(),
        7 => "YXRRSET".to_string(),
        8 => "NXRRSET".to_string(),
        9 => "NOTAUTH".to_string(),
        10 => "NOTZONE".to_string(),
        n => format!("RCODE{}", n),
    }
}

fn txt_chars(rdata: &[u8]) -> String {
    let mut out = String::new();
    let mut p = 0;
    while p < rdata.len() {
        let n = rdata[p] as usize;
        p += 1;
        if p + n > rdata.len() {
            break;
        }
        out.push_str(&String::from_utf8_lossy(&rdata[p..p + n]));
        p += n;
    }
    out
}

fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let rem = data.len() - i;
        let mut n = (data[i] as u32) << 16;
        if rem == 2 {
            n |= (data[i + 1] as u32) << 8;
        }
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if rem == 2 {
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

fn cleanup_loop(log: LogOut, cache: std::sync::Arc<OutputCache>, expiration: Duration, print_interval: Duration, check_interval: Duration) {
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
                    let mut print_rec = state.record.clone();
                    print_rec.count = delta;
                    print_rec.ts = now_iso();
                    emit(&log, &print_rec);
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
                    print_rec.ts = now_iso();
                    emit(&log, &print_rec);

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

fn svc_key_name(key: u16) -> String {
    match key {
        0 => "mandatory".to_string(),
        1 => "alpn".to_string(),
        2 => "no-default-alpn".to_string(),
        3 => "port".to_string(),
        4 => "ipv4hint".to_string(),
        5 => "ech".to_string(),
        6 => "ipv6hint".to_string(),
        7 => "dohpath".to_string(),
        n => format!("key{}", n),
    }
}

fn svc_escape(val: &[u8]) -> String {
    let quote = val.iter().any(|c| c.is_ascii_whitespace());
    let mut out = String::new();
    if quote {
        out.push('"');
    }
    for &c in val {
        if c == b'"' || c == b'\\' {
            out.push('\\');
            out.push(c as char);
        } else if c == b'\t' || (c >= 0x20 && c < 0x7f) {
            out.push(c as char);
        } else {
            out.push_str(&format!("\\{:03}", c));
        }
    }
    if quote {
        out.push('"');
    }
    out
}

fn svc_alpn(val: &[u8]) -> String {
    let mut quote = false;
    let mut p = 0;
    while p < val.len() {
        let n = val[p] as usize;
        p += 1;
        if p + n > val.len() {
            break;
        }
        if val[p..p + n].iter().any(|c| c.is_ascii_whitespace()) {
            quote = true;
        }
        p += n;
    }
    let mut out = String::new();
    if quote {
        out.push('"');
    }
    let mut first = true;
    p = 0;
    while p < val.len() {
        let n = val[p] as usize;
        p += 1;
        if p + n > val.len() {
            break;
        }
        if !first {
            out.push(',');
        }
        first = false;
        for &c in &val[p..p + n] {
            if c == b'"' || c == b'\\' || c == b',' {
                out.push('\\');
                out.push(c as char);
            } else if c == b'\t' || (c >= 0x20 && c < 0x7f) {
                out.push(c as char);
            } else {
                out.push_str(&format!("\\{:03}", c));
            }
        }
        p += n;
    }
    if quote {
        out.push('"');
    }
    out
}

fn parse_https_record(data: &[u8]) -> String {
    if data.len() < 2 {
        return String::new();
    }
    let read_u16 = |b: &[u8]| -> u16 { ((b[0] as u16) << 8) | (b[1] as u16) };
    let mut pos = 0;
    let priority = read_u16(&data[pos..pos + 2]);
    pos += 2;

    let mut target_name = String::new();
    loop {
        if pos >= data.len() {
            break;
        }
        let len = data[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 || pos + len > data.len() {
            return String::new();
        }
        if !target_name.is_empty() {
            target_name.push('.');
        }
        target_name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }
    if target_name.is_empty() {
        target_name = ".".to_string();
    }

    let mut parts = vec![format!("{} {}", priority, target_name)];
    while pos + 4 <= data.len() {
        let key = read_u16(&data[pos..pos + 2]);
        let val_len = read_u16(&data[pos + 2..pos + 4]) as usize;
        pos += 4;
        if pos + val_len > data.len() {
            break;
        }
        let val = &data[pos..pos + val_len];
        pos += val_len;
        let name = svc_key_name(key);
        if val_len == 0 {
            parts.push(name);
            continue;
        }
        let rendered = match key {
            0 => {
                let mut keys = Vec::new();
                let mut i = 0;
                while i + 2 <= val.len() {
                    keys.push(svc_key_name(read_u16(&val[i..i + 2])));
                    i += 2;
                }
                keys.join(",")
            }
            1 => svc_alpn(val),
            3 => {
                if val.len() == 2 {
                    read_u16(val).to_string()
                } else {
                    String::new()
                }
            }
            4 => {
                if val.len() % 4 == 0 {
                    val.chunks(4)
                        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                } else {
                    String::new()
                }
            }
            5 => b64(val),
            6 => {
                if val.len() % 16 == 0 {
                    val.chunks(16)
                        .map(|c| {
                            let mut tmp = [0u8; 16];
                            tmp.copy_from_slice(c);
                            Ipv6Addr::from(tmp).to_string()
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                } else {
                    String::new()
                }
            }
            _ => svc_escape(val),
        };
        if rendered.is_empty() {
            continue;
        }
        parts.push(format!("{}={}", name, rendered));
    }
    parts.join(" ")
}

fn parse_packet(pkt: &PacketObj, reasm: &mut Reassembler, ctx: &ContextMap, cache: &DashMap<String, CacheState>, log: &LogOut) {
    for msg in reasm.push(&pkt.data, pkt.ts) {
        parse_dns(pkt.ts, &msg, ctx, cache, log);
    }
}

fn parse_dns(ts: SystemTime, msg: &L4Msg, ctx: &ContextMap, cache: &DashMap<String, CacheState>, log: &LogOut) {
    let vlan_id = msg.vlan;
    let src_ip = msg.src.clone();
    let dst_ip = msg.dst.clone();
    let src_port = msg.sport;
    let dst_port = msg.dport;
    let proto = msg.proto;
    let payload = msg.payload.as_slice();
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
                    flow.query_name = strip_dot(name.to_string());
                }
                pos += name_len;
                
                if pos + 4 <= payload.len() {
                    let qtype_u16 = read_u16(pos);
                    flow.query_type = type_name(qtype_u16);
                    ctx.insert(key, (flow, ts));
                }
            }
        }
    } else {
        // RESPONSE
        let key = format!("{}:{}:{}:{}", tx_id, proto, dst_ip, dst_port);
        
        // Remove `mut flow` -> just `flow`
        if let Some((_, (flow, start_ts))) = ctx.remove(&key) {
            let latency = ts.duration_since(start_ts).unwrap_or_default().as_secs_f64();
            
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
            let mut last_type = String::new();

            if rcode_val == 0 {
            for _ in 0..an_count {
                if pos >= payload.len() { break; }
                
                let name_len = match get_wire_name_len(payload, pos) {
                    Some(l) => l,
                    None => break,
                };
                pos += name_len;

                if pos + 10 > payload.len() { break; }
                
                let atype = read_u16(pos);
                let attl = ((payload[pos+4] as u32) << 24) | ((payload[pos+5] as u32) << 16) | ((payload[pos+6] as u32) << 8) | (payload[pos+7] as u32);
                let rdlen = read_u16(pos+8) as usize;
                
                pos += 10;

                if pos + rdlen > payload.len() { break; }
                let rdata = &payload[pos..pos+rdlen];

                let ans_str = match atype {
                    1 => {
                        if rdata.len() == 4 {
                             Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()
                        } else { String::new() }
                    },
                    28 => {
                        if rdata.len() == 16 {
                            let mut buf = [0u8; 16];
                            buf.copy_from_slice(rdata);
                            Ipv6Addr::from(buf).to_string()
                        } else { String::new() }
                    },
                    5 | 2 | 12 | 39 => {
                         match Name::scan(rdata, payload) {
                             Ok(n) => strip_dot(n.to_string()),
                             Err(_) => String::new(),
                         }
                    },
                    15 => {
                        if rdata.len() > 2 {
                            let pref = read_u16(pos);
                            match Name::scan(&payload[pos+2..], payload) {
                                Ok(n) => format!("{} {}", pref, strip_dot(n.to_string())),
                                Err(_) => String::new()
                            }
                        } else { String::new() }
                    },
                    33 => {
                        if rdata.len() >= 6 {
                            let pri = read_u16(pos);
                            let weight = read_u16(pos + 2);
                            let port = read_u16(pos + 4);
                            match Name::scan(&payload[pos+6..], payload) {
                                Ok(n) => format!("{} {} {} {}", pri, weight, port, strip_dot(n.to_string())),
                                Err(_) => String::new()
                            }
                        } else { String::new() }
                    },
                    6 => {
                        let mlen = get_wire_name_len(payload, pos).unwrap_or(0);
                        if mlen > 0 && mlen < rdlen {
                            if let Ok(mname) = Name::scan(&payload[pos..], payload) {
                                let rpos = pos + mlen;
                                let rlen = get_wire_name_len(payload, rpos).unwrap_or(0);
                                if rlen > 0 && mlen + rlen + 4 <= rdlen {
                                    if let Ok(rname) = Name::scan(&payload[rpos..], payload) {
                                        let off = pos + mlen + rlen;
                                        let serial = ((payload[off] as u32) << 24)
                                            | ((payload[off + 1] as u32) << 16)
                                            | ((payload[off + 2] as u32) << 8)
                                            | (payload[off + 3] as u32);
                                        format!("{} {} {}", strip_dot(mname.to_string()), strip_dot(rname.to_string()), serial)
                                    } else { String::new() }
                                } else { String::new() }
                            } else { String::new() }
                        } else { String::new() }
                    },
                    16 | 99 => txt_chars(rdata),
                    64 | 65 => parse_https_record(rdata),
                    _ => {
                        if rdlen > 0 { format!("DATA[{} bytes]", rdlen) } else { String::new() }
                    }
                };
                
                if !ans_str.is_empty() {
                    last_type = type_name(atype);
                    ttl_val = attl;
                    answers.push(ans_str);
                }
                pos += rdlen;
            }
            }
            
            answers.sort();

            let rc_str = rcode_name(rcode_val);
            if rcode_val == 0 && answers.is_empty() {
                return;
            }

            let clean_atype = if last_type.is_empty() {
                flow.query_type.clone()
            } else {
                last_type
            };
            
            let record = LogRecord {
                query: flow.query_name.clone(),
                qtype: flow.query_type.clone(),
                answer: answers.clone(),
                atype: clean_atype.clone(),
                rc: rc_str.clone(),
                ttl: ttl_val,
                src_ip: flow.src_ip.clone(),
                dst_ip: flow.dst_ip.clone(),
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                proto: flow.proto,
                vlan: flow.vlan,
                qid: flow.tx_id,
                latency,
                fts: to_iso(start_ts),
                lts: to_iso(ts),
                ts: now_iso(),
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
                state.record.lts = record.lts;
                state.record.src_ip = record.src_ip;
                state.record.dst_ip = record.dst_ip;
                state.record.src_port = record.src_port;
                state.record.dst_port = record.dst_port;
                state.record.proto = record.proto;
                state.record.vlan = record.vlan;
                state.record.qid = record.qid;
                state.record.latency = record.latency;
                if record.ttl > state.record.ttl {
                    state.record.ttl = record.ttl;
                }
                state.last_seen = SystemTime::now();
            } else {
                emit(log, &record);
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

#[cfg(test)]
mod tests {
    use super::LogOut;

    #[test]
    fn logfile_appends_and_keeps_existing_lines() {
        let path = std::env::temp_dir().join(format!(
            "pdnsrust-log-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path_str = path.to_str().expect("temp path");
        LogOut::open(path_str).unwrap().write_line("{\"n\":1}");
        LogOut::open(path_str).unwrap().write_line("{\"n\":2}");
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(text, "{\"n\":1}\n{\"n\":2}\n");
    }
}
