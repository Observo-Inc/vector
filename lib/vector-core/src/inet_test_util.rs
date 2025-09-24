use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use portpicker::pick_unused_port;

pub fn next_addr_for_ip(ip: IpAddr) -> SocketAddr {
    let port = pick_unused_port(ip);
    SocketAddr::new(ip, port)
}

pub fn next_addr() -> SocketAddr {
    next_addr_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

pub fn next_addr_v6() -> SocketAddr {
    next_addr_for_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
}
