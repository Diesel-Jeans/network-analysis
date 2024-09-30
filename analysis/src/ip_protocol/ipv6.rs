use super::ip_protocol;

#[derive(Default)]
pub struct IPv6 {
    pub protocol: [u8; 2],
    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],
}

impl IPv6 {
    fn to_string_addr(addr: [u8; 4]) -> String {
        format!("{}.{}.{}.{} HELLO", addr[0], addr[1], addr[2], addr[3])
    }
}

impl ip_protocol::ToString for IPv6 {
    fn dest_addr(&self) -> String {
        IPv6::to_string_addr(self.dest_addr)
    }

    fn src_addr(&self) -> String {
        IPv6::to_string_addr(self.src_addr)
    }
}
