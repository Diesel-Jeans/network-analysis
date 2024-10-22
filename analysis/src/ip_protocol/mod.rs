pub const ETH_HLEN: usize = 14;
pub const IP_MIN_HLEN: usize = 20;

mod ip_protocol;
pub use ip_protocol::packet_filter;
pub use ip_protocol::Packet;

mod ipv4;
pub use ipv4::IPv4;

mod ipv6;
pub use ipv6::IPv6;
