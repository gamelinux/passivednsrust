// IP fragment reassembly and TCP DNS stream reassembly.
//
// An overlapping fragment drops the whole datagram. A non-last fragment
// must start and end on an 8-byte boundary. Incomplete fragments expire
// after 30 seconds of packet time. A TCP sequence gap drops the partial
// DNS message and resyncs. Each direction has its own buffer, capped at
// one maximum DNS-over-TCP message (65537 bytes, including the length).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

const FRAG_DATA: usize = 65535;
const FRAG_BITS: usize = (FRAG_DATA + 7) / 8;
const UNFRAG_MAX: usize = 512;
const FRAG_MAX: usize = 256;
const FRAG_TIMEOUT: u64 = 30;
const TCP_TIMEOUT: u64 = 300;
const TCP_STREAM_MAX: usize = 65537;
const MAX_IP_TUNNEL: u8 = 3;

const IP_MF: u16 = 0x2000;
const IP_OFFMASK: u16 = 0x1fff;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_IPIP: u8 = 4;
const IP_PROTO_IP4: u8 = 94;
const IP_PROTO_IP6: u8 = 41;
const IP_PROTO_HOPOPTS: u8 = 0;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_AH: u8 = 51;
const IP_PROTO_DSTOPTS: u8 = 60;

const ETHERNET_TYPE_IP: u16 = 0x0800;
const ETHERNET_TYPE_IPV6: u16 = 0x86dd;
const ETHERNET_TYPE_8021Q: u16 = 0x8100;

const UDP_HEADER_LEN: usize = 8;
const TCP_HEADER_LEN: usize = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L4Msg {
    pub vlan: u16,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum IpBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Clone, PartialEq, Eq)]
struct FragKey {
    src: IpBytes,
    dst: IpBytes,
    id: u32,
    proto: u8,
}

struct Frag {
    sid: u64,
    key: FragKey,
    last: u64,
    data: Vec<u8>,
    bits: Vec<u8>,
    hdr: Vec<u8>,
    have_hdr: bool,
    unfrag: Vec<u8>,
    nh_at: usize,
    frag_next: u8,
    have_unfrag: bool,
    total: u16,
    have_last: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    src: IpBytes,
    sport: u16,
    dst: IpBytes,
    dport: u16,
}

#[derive(Default)]
struct TcpDir {
    buf: Vec<u8>,
    expect: u32,
    have_seq: bool,
    last: u64,
}

pub struct Reassembler {
    frags: Vec<Frag>,
    tcp: HashMap<FlowKey, TcpDir>,
    last_sweep: u64,
    next_sid: u64,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            frags: Vec::new(),
            tcp: HashMap::new(),
            last_sweep: 0,
            next_sid: 0,
        }
    }

    /// Returns every UDP payload and every complete TCP DNS message in this
    /// frame. A TCP message does not include its 2-byte length prefix.
    /// The caller stamps each message with the frame that completed it.
    pub fn push(&mut self, frame: &[u8], ts: SystemTime) -> Vec<L4Msg> {
        let secs = packet_secs(ts);
        self.expire(secs);
        let mut out = Vec::new();
        let Some((vlan, hlen, etype)) = parse_eth(frame) else {
            return out;
        };
        match etype {
            ETHERNET_TYPE_IP => self.walk_ip4(frame, hlen, vlan, secs, 0, &mut out),
            ETHERNET_TYPE_IPV6 => self.walk_ip6(frame, hlen, vlan, secs, 0, &mut out),
            _ => {}
        }
        out
    }

    fn expire(&mut self, now: u64) {
        if now <= self.last_sweep {
            return;
        }
        self.last_sweep = now;
        self.frags
            .retain(|f| now <= f.last || now - f.last < FRAG_TIMEOUT);
        self.tcp
            .retain(|_, d| now <= d.last || now - d.last <= TCP_TIMEOUT);
    }

    fn walk_ip4(
        &mut self,
        pkt: &[u8],
        eth_hlen: usize,
        vlan: u16,
        secs: u64,
        tunnel: u8,
        out: &mut Vec<L4Msg>,
    ) {
        if eth_hlen + 20 > pkt.len() || pkt[eth_hlen] >> 4 != 4 {
            return;
        }
        let ihl = (pkt[eth_hlen] & 0x0f) as usize;
        if ihl < 5 {
            return;
        }
        let ihl_bytes = ihl * 4;
        if eth_hlen + ihl_bytes > pkt.len() {
            return;
        }
        let ip_len = be_u16(pkt, eth_hlen + 2) as usize;
        if ip_len < ihl_bytes {
            return;
        }
        let foff = be_u16(pkt, eth_hlen + 6);
        if foff & (IP_MF | IP_OFFMASK) != 0 {
            self.ip4_defrag(pkt, eth_hlen, ihl_bytes, ip_len, foff, vlan, secs, tunnel, out);
            return;
        }
        let proto = pkt[eth_hlen + 9];
        let l4 = eth_hlen + ihl_bytes;
        let src = IpBytes::V4(copy4(pkt, eth_hlen + 12));
        let dst = IpBytes::V4(copy4(pkt, eth_hlen + 16));
        match proto {
            IP_PROTO_TCP | IP_PROTO_UDP => {
                let dend = dg_end(pkt, eth_hlen, ip_len);
                self.dispatch_l4(pkt, l4, dend, proto, src, dst, vlan, secs, out);
            }
            IP_PROTO_IPIP | IP_PROTO_IP4 | IP_PROTO_IP6 => {
                self.tunnel(pkt, l4, eth_hlen, proto == IP_PROTO_IP6, vlan, secs, tunnel, out);
            }
            _ => {}
        }
    }

    fn walk_ip6(
        &mut self,
        pkt: &[u8],
        eth_hlen: usize,
        vlan: u16,
        secs: u64,
        tunnel: u8,
        out: &mut Vec<L4Msg>,
    ) {
        if eth_hlen + 40 > pkt.len() || pkt[eth_hlen] >> 4 != 6 {
            return;
        }
        let plen = be_u16(pkt, eth_hlen + 4) as usize;
        let end = match eth_hlen
            .checked_add(40)
            .and_then(|n| n.checked_add(plen))
        {
            Some(claimed) => claimed.min(pkt.len()),
            None => pkt.len(),
        };
        let src = IpBytes::V6(copy16(pkt, eth_hlen + 8));
        let dst = IpBytes::V6(copy16(pkt, eth_hlen + 24));
        let mut nxt = pkt[eth_hlen + 6];
        let mut cur = eth_hlen + 40;
        let mut nh_ptr = eth_hlen + 6;
        let mut depth = 0;
        while depth < 8 {
            depth += 1;
            if nxt == IP_PROTO_TCP || nxt == IP_PROTO_UDP {
                self.dispatch_l4(pkt, cur, end, nxt, src, dst, vlan, secs, out);
                return;
            }
            if nxt == IP_PROTO_IPIP || nxt == IP_PROTO_IP4 || nxt == IP_PROTO_IP6 {
                self.tunnel(pkt, cur, eth_hlen, nxt == IP_PROTO_IP6, vlan, secs, tunnel, out);
                return;
            }
            if nxt == IP_PROTO_HOPOPTS || nxt == IP_PROTO_DSTOPTS || nxt == IP_PROTO_ROUTING {
                let Some((next, next_cur)) = skip_ext(pkt, cur, end, 1, 8) else {
                    return;
                };
                nh_ptr = cur;
                nxt = next;
                cur = next_cur;
                continue;
            }
            if nxt == IP_PROTO_AH {
                let Some((next, next_cur)) = skip_ext(pkt, cur, end, 2, 4) else {
                    return;
                };
                nh_ptr = cur;
                nxt = next;
                cur = next_cur;
                continue;
            }
            if nxt == IP_PROTO_FRAGMENT {
                if cur + 8 > pkt.len() || cur + 8 > end || cur < eth_hlen {
                    return;
                }
                let offm = be_u16(pkt, cur + 2);
                let off_bytes = ((offm >> 3) as u32) << 3;
                let more = offm & 1 != 0;
                let id = be_u32(pkt, cur + 4);
                let frag_at = cur + 8;
                if frag_at > end {
                    return;
                }
                let fraglen = end - frag_at;
                if off_bytes == 0 && !more {
                    nxt = pkt[cur];
                    nh_ptr = cur;
                    cur = frag_at;
                    continue;
                }
                let unfrag_len = cur - eth_hlen;
                if unfrag_len > 65535 {
                    return;
                }
                let nh_at = nh_ptr - eth_hlen;
                let frag_next = pkt[cur];
                self.ip6_defrag(
                    pkt, eth_hlen, unfrag_len, nh_at, frag_next, id, off_bytes, more, frag_at,
                    fraglen, src, dst, vlan, secs, tunnel, out,
                );
                return;
            }
            return;
        }
    }

    fn tunnel(
        &mut self,
        pkt: &[u8],
        l4: usize,
        eth_hlen: usize,
        as_v6: bool,
        vlan: u16,
        secs: u64,
        tunnel: u8,
        out: &mut Vec<L4Msg>,
    ) {
        if tunnel >= MAX_IP_TUNNEL || l4 <= eth_hlen || l4 > pkt.len() {
            return;
        }
        let inner = &pkt[l4..];
        if as_v6 {
            self.walk_ip6(inner, 0, vlan, secs, tunnel + 1, out);
        } else {
            self.walk_ip4(inner, 0, vlan, secs, tunnel + 1, out);
        }
    }

    fn dispatch_l4(
        &mut self,
        pkt: &[u8],
        l4: usize,
        dend: usize,
        proto: u8,
        src: IpBytes,
        dst: IpBytes,
        vlan: u16,
        secs: u64,
        out: &mut Vec<L4Msg>,
    ) {
        if proto == IP_PROTO_UDP {
            emit_udp(pkt, l4, dend, src, dst, vlan, out);
        } else if proto == IP_PROTO_TCP {
            self.emit_tcp(pkt, l4, dend, src, dst, vlan, secs, out);
        }
    }

    fn ip4_defrag(
        &mut self,
        pkt: &[u8],
        eth_hlen: usize,
        ihl_bytes: usize,
        ip_len: usize,
        foff: u16,
        vlan: u16,
        secs: u64,
        tunnel: u8,
        out: &mut Vec<L4Msg>,
    ) {
        let off_bytes = ((u32::from(foff & IP_OFFMASK)) << 3) as u16;
        let more = foff & IP_MF != 0;
        let pay_at = eth_hlen + ihl_bytes;
        if pay_at > pkt.len() {
            return;
        }
        let mut pay_len = ip_len - ihl_bytes;
        if pay_at + pay_len > pkt.len() {
            pay_len = pkt.len() - pay_at;
        }
        if pay_len == 0 {
            return;
        }
        let pay = pkt[pay_at..pay_at + pay_len].to_vec();
        let key = FragKey {
            src: IpBytes::V4(copy4(pkt, eth_hlen + 12)),
            dst: IpBytes::V4(copy4(pkt, eth_hlen + 16)),
            id: u32::from(be_u16(pkt, eth_hlen + 4)),
            proto: pkt[eth_hlen + 9],
        };
        let Some(sid) = self.touch_frag(key, secs) else {
            return;
        };
        let mut drop_it = false;
        let mut built = None;
        if let Some(f) = self.frags.iter_mut().find(|f| f.sid == sid) {
            if off_bytes == 0 {
                if ihl_bytes > 60 {
                    drop_it = true;
                } else {
                    f.hdr = pkt[eth_hlen..eth_hlen + ihl_bytes].to_vec();
                    f.have_hdr = true;
                }
            }
            if !drop_it && !take_piece(f, off_bytes, more, &pay) {
                drop_it = true;
            }
            if !drop_it && frag_complete(f) && f.have_hdr {
                let total = f.total as usize;
                if f.hdr.len() + total > 65535 {
                    drop_it = true;
                } else {
                    let mut pktb = Vec::with_capacity(f.hdr.len() + total);
                    pktb.extend_from_slice(&f.hdr);
                    pktb.extend_from_slice(&f.data[..total]);
                    let n = (f.hdr.len() + total) as u16;
                    pktb[2] = (n >> 8) as u8;
                    pktb[3] = (n & 0xff) as u8;
                    pktb[6] = 0;
                    pktb[7] = 0;
                    built = Some(pktb);
                }
            }
        }
        if drop_it {
            self.remove_sid(sid);
            return;
        }
        if let Some(pktb) = built {
            self.walk_ip4(&pktb, 0, vlan, secs, tunnel, out);
            self.remove_sid(sid);
        }
    }

    fn ip6_defrag(
        &mut self,
        pkt: &[u8],
        eth_hlen: usize,
        unfrag_len: usize,
        nh_at: usize,
        frag_next: u8,
        id: u32,
        off_bytes: u32,
        more: bool,
        frag_at: usize,
        fraglen: usize,
        src: IpBytes,
        dst: IpBytes,
        vlan: u16,
        secs: u64,
        tunnel: u8,
        out: &mut Vec<L4Msg>,
    ) {
        if unfrag_len < 40 || unfrag_len > UNFRAG_MAX || nh_at >= unfrag_len {
            return;
        }
        if eth_hlen + unfrag_len > pkt.len() || frag_at + fraglen > pkt.len() {
            return;
        }
        let unfrag = pkt[eth_hlen..eth_hlen + unfrag_len].to_vec();
        let frag = pkt[frag_at..frag_at + fraglen].to_vec();
        let key = FragKey {
            src,
            dst,
            id,
            proto: IP_PROTO_FRAGMENT,
        };
        let Some(sid) = self.touch_frag(key, secs) else {
            return;
        };
        let off_u = u16::try_from(off_bytes).unwrap_or(u16::MAX);
        if off_bytes > u32::from(u16::MAX) {
            self.remove_sid(sid);
            return;
        }
        let mut drop_it = false;
        let mut built = None;
        if let Some(f) = self.frags.iter_mut().find(|f| f.sid == sid) {
            if off_bytes == 0 {
                f.unfrag = unfrag;
                f.nh_at = nh_at;
                f.frag_next = frag_next;
                f.have_unfrag = true;
            }
            if !take_piece(f, off_u, more, &frag) {
                drop_it = true;
            }
            if !drop_it && frag_complete(f) && f.have_unfrag {
                let total = f.total as usize;
                match f.unfrag.len().checked_add(total) {
                    Some(pktlen) if pktlen >= f.unfrag.len() && pktlen - 40 <= 65535 => {
                        let mut pktb = Vec::with_capacity(pktlen);
                        pktb.extend_from_slice(&f.unfrag);
                        if f.nh_at < pktb.len() {
                            pktb[f.nh_at] = f.frag_next;
                            pktb.extend_from_slice(&f.data[..total]);
                            let plen = (pktb.len() - 40) as u16;
                            pktb[4] = (plen >> 8) as u8;
                            pktb[5] = (plen & 0xff) as u8;
                            built = Some(pktb);
                        } else {
                            drop_it = true;
                        }
                    }
                    _ => drop_it = true,
                }
            }
        }
        if drop_it {
            self.remove_sid(sid);
            return;
        }
        if let Some(pktb) = built {
            self.walk_ip6(&pktb, 0, vlan, secs, tunnel, out);
            self.remove_sid(sid);
        }
    }

    fn touch_frag(&mut self, key: FragKey, secs: u64) -> Option<u64> {
        if let Some(f) = self.frags.iter_mut().find(|f| f.key == key) {
            f.last = secs;
            return Some(f.sid);
        }
        if self.frags.len() >= FRAG_MAX {
            return None;
        }
        self.next_sid += 1;
        let sid = self.next_sid;
        self.frags.push(Frag {
            sid,
            key,
            last: secs,
            data: vec![0u8; FRAG_DATA],
            bits: vec![0u8; FRAG_BITS],
            hdr: Vec::new(),
            have_hdr: false,
            unfrag: Vec::new(),
            nh_at: 0,
            frag_next: 0,
            have_unfrag: false,
            total: 0,
            have_last: false,
        });
        Some(sid)
    }

    fn remove_sid(&mut self, sid: u64) {
        self.frags.retain(|f| f.sid != sid);
    }

    fn emit_tcp(
        &mut self,
        pkt: &[u8],
        l4: usize,
        dend: usize,
        src: IpBytes,
        dst: IpBytes,
        vlan: u16,
        secs: u64,
        out: &mut Vec<L4Msg>,
    ) {
        if l4 + TCP_HEADER_LEN > pkt.len() {
            return;
        }
        let doff = (pkt[l4 + 12] >> 4) as usize;
        if doff < 5 {
            return;
        }
        let hdr = doff * 4;
        if l4 + hdr > pkt.len() {
            return;
        }
        let payload_off = l4 + hdr;
        if payload_off > dend {
            return;
        }
        let plen = dend.saturating_sub(payload_off).min(pkt.len().saturating_sub(payload_off));
        let sport = be_u16(pkt, l4);
        let dport = be_u16(pkt, l4 + 2);
        let seq = be_u32(pkt, l4 + 4);
        let syn = pkt[l4 + 13] & 0x02 != 0;
        let payload = pkt[payload_off..payload_off + plen].to_vec();
        self.tcp_segment(
            FlowKey { src, sport, dst, dport },
            seq,
            syn,
            &payload,
            vlan,
            secs,
            out,
        );
    }

    fn tcp_segment(
        &mut self,
        key: FlowKey,
        seq: u32,
        syn: bool,
        payload: &[u8],
        vlan: u16,
        secs: u64,
        out: &mut Vec<L4Msg>,
    ) {
        let dir = self.tcp.entry(key).or_default();
        dir.last = secs;
        let data_seq = seq.wrapping_add(u32::from(syn));
        let plen = payload.len();
        let seg_end = data_seq.wrapping_add(plen as u32);
        if !dir.have_seq {
            dir.expect = data_seq;
            dir.have_seq = true;
        }
        if plen == 0 {
            return;
        }
        if (data_seq.wrapping_sub(dir.expect) as i32) > 0 {
            dir.buf.clear();
            dir.expect = data_seq;
        }
        let mut view = payload;
        if (data_seq.wrapping_sub(dir.expect) as i32) < 0 {
            let skip = dir.expect.wrapping_sub(data_seq) as usize;
            if skip >= view.len() {
                return;
            }
            view = &view[skip..];
        }
        if view.len() > TCP_STREAM_MAX || dir.buf.len() > TCP_STREAM_MAX - view.len() {
            dir.buf.clear();
            dir.have_seq = true;
            dir.expect = seg_end;
            return;
        }
        dir.buf.extend_from_slice(view);
        dir.expect = seg_end;

        let src = format_ip(key.src);
        let dst = format_ip(key.dst);
        while dir.buf.len() >= 2 {
            let mlen = u16::from_be_bytes([dir.buf[0], dir.buf[1]]) as usize;
            if mlen < 12 || mlen + 2 > TCP_STREAM_MAX {
                dir.buf.clear();
                return;
            }
            if dir.buf.len() < mlen + 2 {
                return;
            }
            let msg = dir.buf[2..2 + mlen].to_vec();
            let rest = dir.buf[2 + mlen..].to_vec();
            dir.buf = rest;
            out.push(L4Msg {
                vlan,
                src: src.clone(),
                dst: dst.clone(),
                sport: key.sport,
                dport: key.dport,
                proto: IP_PROTO_TCP,
                payload: msg,
            });
        }
    }
}

fn emit_udp(
    pkt: &[u8],
    l4: usize,
    dend: usize,
    src: IpBytes,
    dst: IpBytes,
    vlan: u16,
    out: &mut Vec<L4Msg>,
) {
    if l4 + UDP_HEADER_LEN > pkt.len() {
        return;
    }
    let ulen = be_u16(pkt, l4 + 4) as usize;
    if ulen < UDP_HEADER_LEN {
        return;
    }
    let payload_off = l4 + UDP_HEADER_LEN;
    if payload_off > dend {
        return;
    }
    let have = dend - payload_off;
    let claimed = ulen - UDP_HEADER_LEN;
    let plen = claimed.min(have).min(pkt.len().saturating_sub(payload_off));
    out.push(L4Msg {
        vlan,
        src: format_ip(src),
        dst: format_ip(dst),
        sport: be_u16(pkt, l4),
        dport: be_u16(pkt, l4 + 2),
        proto: IP_PROTO_UDP,
        payload: pkt[payload_off..payload_off + plen].to_vec(),
    });
}

fn take_piece(f: &mut Frag, off: u16, more: bool, payload: &[u8]) -> bool {
    let off = off as usize;
    let len = payload.len();
    if len == 0 || off + len > FRAG_DATA {
        return false;
    }
    if more && (len & 7) != 0 {
        return false;
    }
    if more && ((off + len) & 7) != 0 {
        return false;
    }
    if !frag_cover(f, off, payload) {
        return false;
    }
    if !more {
        let total = off + len;
        if f.have_last && f.total as usize != total {
            return false;
        }
        f.have_last = true;
        f.total = total as u16;
    } else if f.have_last && off + len > f.total as usize {
        return false;
    }
    true
}

fn frag_cover(f: &mut Frag, off: usize, payload: &[u8]) -> bool {
    if off + payload.len() > FRAG_DATA {
        return false;
    }
    for i in 0..payload.len() {
        if bit_test(&f.bits, off + i) {
            return false;
        }
    }
    f.data[off..off + payload.len()].copy_from_slice(payload);
    for i in 0..payload.len() {
        bit_set(&mut f.bits, off + i);
    }
    true
}

fn frag_complete(f: &Frag) -> bool {
    if !f.have_last || f.total == 0 {
        return false;
    }
    for i in 0..f.total as usize {
        if !bit_test(&f.bits, i) {
            return false;
        }
    }
    true
}

fn bit_test(bits: &[u8], i: usize) -> bool {
    (bits[i >> 3] >> (i & 7)) & 1 == 1
}

fn bit_set(bits: &mut [u8], i: usize) {
    bits[i >> 3] |= 1 << (i & 7);
}

fn skip_ext(pkt: &[u8], cur: usize, end: usize, extra: usize, unit: usize) -> Option<(u8, usize)> {
    if cur + 2 > pkt.len() || cur + 2 > end {
        return None;
    }
    let skip = (pkt[cur + 1] as usize + extra).checked_mul(unit)?;
    if skip == 0 || cur + skip > pkt.len() || cur + skip > end {
        return None;
    }
    Some((pkt[cur], cur + skip))
}

fn parse_eth(frame: &[u8]) -> Option<(u16, usize, u16)> {
    if frame.len() < 14 {
        return None;
    }
    let mut etype = be_u16(frame, 12);
    let mut hlen = 14usize;
    let mut vlan = 0u16;
    if etype == ETHERNET_TYPE_8021Q {
        if frame.len() < 18 {
            return None;
        }
        vlan = be_u16(frame, 14) & 0x0fff;
        etype = be_u16(frame, 16);
        hlen = 18;
        if etype == ETHERNET_TYPE_8021Q {
            if frame.len() < 22 {
                return None;
            }
            vlan = be_u16(frame, 18) & 0x0fff;
            etype = be_u16(frame, 20);
            hlen = 22;
        }
    } else if matches!(etype, 0x9100 | 0x9200 | 0x9300 | 0x88a8) {
        if frame.len() < 22 {
            return None;
        }
        etype = be_u16(frame, 20);
        hlen = 22;
    }
    Some((vlan, hlen, etype))
}

fn dg_end(pkt: &[u8], eth_hlen: usize, span: usize) -> usize {
    if eth_hlen >= pkt.len() {
        return pkt.len();
    }
    eth_hlen + span.min(pkt.len() - eth_hlen)
}

fn packet_secs(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn format_ip(ip: IpBytes) -> String {
    match ip {
        IpBytes::V4(b) => Ipv4Addr::from(b).to_string(),
        IpBytes::V6(b) => Ipv6Addr::from(b).to_string(),
    }
}

fn copy4(b: &[u8], o: usize) -> [u8; 4] {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    a
}

fn copy16(b: &[u8], o: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    a
}

fn be_u16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn be_u32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(sec: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(sec)
    }

    fn wire_name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for part in n.split('.') {
            out.push(part.len() as u8);
            out.extend(part.as_bytes());
        }
        out.push(0);
        out
    }

    fn dns_query(tid: u16, qname: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(tid.to_be_bytes());
        v.extend(0x0100u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v.extend([0u8; 6]);
        v.extend(wire_name(qname));
        v.extend(1u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v
    }

    fn dns_response(tid: u16, qname: &str, rdata: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(tid.to_be_bytes());
        v.extend(0x8180u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        let n = wire_name(qname);
        v.extend(n.iter().copied());
        v.extend(1u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v.extend(n);
        v.extend(1u16.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v.extend(300u32.to_be_bytes());
        v.extend((rdata.len() as u16).to_be_bytes());
        v.extend(rdata);
        v
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8], ident: u16, off: u16) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut v = vec![0x45, 0];
        v.extend(total.to_be_bytes());
        v.extend(ident.to_be_bytes());
        v.extend(off.to_be_bytes());
        v.push(64);
        v.push(proto);
        v.extend(0u16.to_be_bytes());
        v.extend(src);
        v.extend(dst);
        v.extend(payload);
        v
    }

    fn ipv6(src: [u8; 16], dst: [u8; 16], nxt: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(0x6000_0000u32.to_be_bytes());
        v.extend((payload.len() as u16).to_be_bytes());
        v.push(nxt);
        v.push(64);
        v.extend(src);
        v.extend(dst);
        v.extend(payload);
        v
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(sport.to_be_bytes());
        v.extend(dport.to_be_bytes());
        v.extend(((8 + payload.len()) as u16).to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend(payload);
        v
    }

    fn tcp(sport: u16, dport: u16, seq: u32, payload: &[u8], flags: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(sport.to_be_bytes());
        v.extend(dport.to_be_bytes());
        v.extend(seq.to_be_bytes());
        v.extend(0u32.to_be_bytes());
        v.push(5 << 4);
        v.push(flags);
        v.extend(65535u16.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend(0u16.to_be_bytes());
        v.extend(payload);
        v
    }

    fn eth(payload: &[u8], etype: u16) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v.extend(etype.to_be_bytes());
        v.extend(payload);
        v
    }

    fn eth_vlan(payload: &[u8], vid: u16) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v.extend(0x8100u16.to_be_bytes());
        v.extend((vid & 0x0fff).to_be_bytes());
        v.extend(0x0800u16.to_be_bytes());
        v.extend(payload);
        v
    }

    fn v6(text: &str) -> [u8; 16] {
        text.parse::<Ipv6Addr>().unwrap().octets()
    }

    fn feed(frames: &[Vec<u8>]) -> Vec<L4Msg> {
        let mut r = Reassembler::new();
        let mut out = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            out.extend(r.push(frame, at(1_700_000_000 + i as u64)));
        }
        out
    }

    fn prefixed(msg: &[u8]) -> Vec<u8> {
        let mut v = (msg.len() as u16).to_be_bytes().to_vec();
        v.extend(msg);
        v
    }

    #[test]
    fn udp_payload_is_the_dns_message() {
        let q = dns_query(0x1234, "a.example.com");
        let frame = eth(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(40000, 53, &q), 1, 0), 0x0800);
        let msgs = feed(&[frame]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
        assert_eq!(msgs[0].src, "10.0.0.1");
        assert_eq!(msgs[0].dst, "10.0.0.2");
        assert_eq!(msgs[0].sport, 40000);
        assert_eq!(msgs[0].dport, 53);
        assert_eq!(msgs[0].proto, 17);
        assert_eq!(msgs[0].vlan, 0);
    }

    #[test]
    fn ethernet_padding_is_not_part_of_the_udp_payload() {
        let q = dns_query(0x1234, "a.example.com");
        let mut frame = eth(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(40000, 53, &q), 1, 0), 0x0800);
        frame.extend([0xff; 20]);
        let msgs = feed(&[frame]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn ipv4_fragments_yield_the_dns_payload() {
        let q = dns_query(0x1234, "a.example.com");
        let a = dns_response(0x1234, "a.example.com", &[9, 9, 9, 9]);
        let udp_dg = udp(53, 40000, &a);
        let (frag1, frag2) = udp_dg.split_at(64);
        let msgs = feed(&[
            eth(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(40000, 53, &q), 1, 0), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag1, 9, 0x2000), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag2, 9, 64 / 8), 0x0800),
        ]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, q);
        assert_eq!(msgs[1].payload, a);
        assert_eq!(msgs[1].sport, 53);
        assert_eq!(msgs[1].dport, 40000);
        assert_eq!(msgs[1].src, "10.0.0.2");
    }

    #[test]
    fn ipv4_overlap_drops_the_datagram() {
        let q = dns_query(0x1234, "a.example.com");
        let a = dns_response(0x1234, "a.example.com", &[9, 9, 9, 9]);
        let udp_dg = udp(53, 40000, &a);
        let (frag1, frag2) = udp_dg.split_at(64);
        let msgs = feed(&[
            eth(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(40000, 53, &q), 1, 0), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag1, 9, 0x2000), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag1, 9, 0x2000), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag2, 9, 64 / 8), 0x0800),
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn ipv4_out_of_order_fragments_still_yield() {
        let a = dns_response(0x1234, "a.example.com", &[9, 9, 9, 9]);
        let udp_dg = udp(53, 40000, &a);
        let (frag1, frag2) = udp_dg.split_at(64);
        let msgs = feed(&[
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag2, 11, 64 / 8), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag1, 11, 0x2000), 0x0800),
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, a);
    }

    #[test]
    fn ipv4_unaligned_fragment_yields_nothing() {
        let q = dns_query(0x1234, "a.example.com");
        let a = dns_response(0x1234, "a.example.com", &[9, 9, 9, 9]);
        let udp_dg = udp(53, 40000, &a);
        let msgs = feed(&[
            eth(&ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(40000, 53, &q), 1, 0), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, &udp_dg[..20], 12, 0x2000), 0x0800),
            eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, &udp_dg[20..], 12, 20 / 8), 0x0800),
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn ipv4_fragment_expires_after_thirty_seconds() {
        let a = dns_response(0x1234, "a.example.com", &[9, 9, 9, 9]);
        let udp_dg = udp(53, 40000, &a);
        let (frag1, frag2) = udp_dg.split_at(64);
        let mut r = Reassembler::new();
        let first = eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag1, 9, 0x2000), 0x0800);
        let second = eth(&ipv4([10, 0, 0, 2], [10, 0, 0, 1], 17, frag2, 9, 64 / 8), 0x0800);
        assert!(r.push(&first, at(1_000)).is_empty());
        assert!(r.push(&second, at(1_030)).is_empty());

        let mut r = Reassembler::new();
        assert!(r.push(&first, at(1_000)).is_empty());
        let msgs = r.push(&second, at(1_029));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, a);
    }

    #[test]
    fn ipv6_fragments_yield_the_dns_payload() {
        let src = v6("2001:db8::1");
        let dst = v6("2001:db8::2");
        let q = dns_query(0x2222, "v6.example.com");
        let a = dns_response(0x2222, "v6.example.com", &[8, 8, 8, 8]);
        let udp_dg = udp(53, 40000, &a);
        let (f6a, f6b) = udp_dg.split_at(64);
        let frag_a = {
            let mut h = vec![17, 0];
            h.extend(0x0001u16.to_be_bytes());
            h.extend(7u32.to_be_bytes());
            h.extend(f6a);
            h
        };
        let frag_b = {
            let mut h = vec![17, 0];
            h.extend(((8u16) << 3).to_be_bytes());
            h.extend(7u32.to_be_bytes());
            h.extend(f6b);
            h
        };
        let msgs = feed(&[
            eth(&ipv6(src, dst, 17, &udp(40000, 53, &q)), 0x86dd),
            eth(&ipv6(dst, src, 44, &frag_a), 0x86dd),
            eth(&ipv6(dst, src, 44, &frag_b), 0x86dd),
        ]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].payload, a);
        assert_eq!(msgs[1].src, "2001:db8::2");
        assert_eq!(msgs[1].dst, "2001:db8::1");
    }

    #[test]
    fn ipv6_hop_by_hop_then_fragment() {
        let src = v6("2001:db8::1");
        let dst = v6("2001:db8::2");
        let q = dns_query(0x4242, "hbhfrag.example.com");
        let a = dns_response(0x4242, "hbhfrag.example.com", &[9, 9, 9, 9]);
        let udp_dg = udp(53, 40000, &a);
        let hbh = {
            let mut h = vec![44, 0];
            h.extend([0u8; 6]);
            h
        };
        let mut first = hbh.clone();
        first.extend([17, 0]);
        first.extend(0x0001u16.to_be_bytes());
        first.extend(7u32.to_be_bytes());
        first.extend(&udp_dg[..64]);
        let mut second = hbh;
        second.extend([17, 0]);
        second.extend(((8u16) << 3).to_be_bytes());
        second.extend(7u32.to_be_bytes());
        second.extend(&udp_dg[64..]);
        let msgs = feed(&[
            eth(&ipv6(src, dst, 17, &udp(40000, 53, &q)), 0x86dd),
            eth(&ipv6(dst, src, 0, &first), 0x86dd),
            eth(&ipv6(dst, src, 0, &second), 0x86dd),
        ]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].payload, a);
    }

    #[test]
    fn ipv6_hop_by_hop_to_udp() {
        let src = v6("2001:db8::1");
        let dst = v6("2001:db8::2");
        let q = dns_query(0x3333, "hop.example.com");
        let a = dns_response(0x3333, "hop.example.com", &[1, 2, 3, 4]);
        let hop = {
            let mut h = vec![17, 0];
            h.extend([0u8; 6]);
            h
        };
        let mut qpkt = hop.clone();
        qpkt.extend(udp(40000, 53, &q));
        let mut apkt = hop;
        apkt.extend(udp(53, 40000, &a));
        let msgs = feed(&[
            eth(&ipv6(src, dst, 0, &qpkt), 0x86dd),
            eth(&ipv6(dst, src, 0, &apkt), 0x86dd),
        ]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, q);
        assert_eq!(msgs[1].payload, a);
        assert_eq!(msgs[0].src, "2001:db8::1");
    }

    #[test]
    fn ipv6_atomic_fragment_is_not_reassembled() {
        let src = v6("2001:db8::1");
        let dst = v6("2001:db8::2");
        let a = dns_response(0x7abd, "atomic.example.com", &[9, 9, 9, 9]);
        let mut atomic = vec![17, 0, 0, 0];
        atomic.extend(9u32.to_be_bytes());
        atomic.extend(udp(53, 48002, &a));
        let msgs = feed(&[eth(&ipv6(dst, src, 44, &atomic), 0x86dd)]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, a);
    }

    #[test]
    fn tcp_split_message_is_one_dns_payload() {
        let q = dns_query(0x4444, "tcp.example.com");
        let a = dns_response(0x4444, "tcp.example.com", &[5, 6, 7, 8]);
        let qmsg = prefixed(&q);
        let amsg = prefixed(&a);
        let msgs = feed(&[
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41000, 53, 1000, &qmsg[..10], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41000, 53, 1010, &qmsg[10..], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 2], [10, 1, 0, 1], 6, &tcp(53, 41000, 5000, &amsg, 0x18), 1, 0), 0x0800),
        ]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, q);
        assert_eq!(msgs[0].proto, 6);
        assert_eq!(msgs[1].payload, a);
        assert_eq!(msgs[1].sport, 53);
    }

    #[test]
    fn tcp_sequence_gap_drops_the_partial_query() {
        let q = dns_query(0x4444, "tcp.example.com");
        let a = dns_response(0x4444, "tcp.example.com", &[5, 6, 7, 8]);
        let qmsg = prefixed(&q);
        let amsg = prefixed(&a);
        let msgs = feed(&[
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41001, 53, 1000, &qmsg[..10], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41001, 53, 1030, &qmsg[10..], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 2], [10, 1, 0, 1], 6, &tcp(53, 41001, 5000, &amsg, 0x18), 1, 0), 0x0800),
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, a);
    }

    #[test]
    fn tcp_retransmit_of_the_first_chunk_yields_one_message() {
        let q = dns_query(0x7ccc, "re.example.com");
        let a = dns_response(0x7ccc, "re.example.com", &[5, 6, 7, 8]);
        let qmsg = prefixed(&q);
        let amsg = prefixed(&a);
        let msgs = feed(&[
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41002, 53, 1000, &qmsg[..10], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41002, 53, 1000, &qmsg[..10], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41002, 53, 1010, &qmsg[10..], 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 2], [10, 1, 0, 1], 6, &tcp(53, 41002, 5000, &amsg, 0x18), 1, 0), 0x0800),
        ]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, q);
        assert_eq!(msgs[1].payload, a);
    }

    #[test]
    fn tcp_syn_consumes_one_sequence_number() {
        let q = dns_query(0x4444, "syn.example.com");
        let qmsg = prefixed(&q);
        let msgs = feed(&[
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41003, 53, 1000, &qmsg[..10], 0x02), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41003, 53, 1011, &qmsg[10..], 0x18), 1, 0), 0x0800),
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn tcp_two_messages_in_one_segment() {
        let q1 = dns_query(0x1001, "one.example.com");
        let q2 = dns_query(0x1002, "two.example.com");
        let mut both = prefixed(&q1);
        both.extend(prefixed(&q2));
        let msgs = feed(&[eth(
            &ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41004, 53, 50, &both, 0x18), 1, 0),
            0x0800,
        )]);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload, q1);
        assert_eq!(msgs[1].payload, q2);
    }

    #[test]
    fn tcp_short_length_drops_the_buffer_and_the_next_message_still_parses() {
        let q = dns_query(0x4444, "next.example.com");
        let qmsg = prefixed(&q);
        let junk = [0x00, 0x05, 1, 2, 3, 4, 5];
        let msgs = feed(&[
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41005, 53, 1000, &junk, 0x18), 1, 0), 0x0800),
            eth(&ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41005, 53, 1007, &qmsg, 0x18), 1, 0), 0x0800),
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn tcp_idle_direction_expires_after_three_hundred_seconds() {
        let q = dns_query(0x4444, "idle.example.com");
        let qmsg = prefixed(&q);
        let mut r = Reassembler::new();
        let first = eth(
            &ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41006, 53, 1000, &qmsg[..10], 0x18), 1, 0),
            0x0800,
        );
        let second = eth(
            &ipv4([10, 1, 0, 1], [10, 1, 0, 2], 6, &tcp(41006, 53, 1010, &qmsg[10..], 0x18), 1, 0),
            0x0800,
        );
        assert!(r.push(&first, at(5_000)).is_empty());
        assert!(r.push(&second, at(5_301)).is_empty());

        let mut r = Reassembler::new();
        assert!(r.push(&first, at(5_000)).is_empty());
        let msgs = r.push(&second, at(5_300));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn vlan_identifier_is_kept() {
        let q = dns_query(0x7001, "vlan.example.com");
        let frame = eth_vlan(&ipv4([10, 6, 0, 1], [10, 6, 0, 2], 17, &udp(45000, 53, &q), 1, 0), 100);
        let msgs = feed(&[frame]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].vlan, 100);
        assert_eq!(msgs[0].payload, q);
    }

    #[test]
    fn ipv4_in_ipv4_reaches_the_inner_dns_message() {
        let q = dns_query(0x1111, "tunnel.example.com");
        let inner = ipv4([10, 9, 0, 1], [10, 9, 0, 2], 17, &udp(40000, 53, &q), 1, 0);
        let outer = ipv4([10, 8, 0, 1], [10, 8, 0, 2], 4, &inner, 2, 0);
        let msgs = feed(&[eth(&outer, 0x0800)]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, q);
        assert_eq!(msgs[0].src, "10.9.0.1");
        assert_eq!(msgs[0].dst, "10.9.0.2");
    }
}
