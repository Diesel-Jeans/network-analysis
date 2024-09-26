use core::str;

#[derive(Default)]
pub struct IPv4 {
    pub protocol: [u8; 2],
    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],
}

impl IPv4 {
    fn to_string_addr(addr: [u8; 4]) -> String {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }

    pub fn to_string_src_addr(&self) -> String {
        IPv4::to_string_addr(self.src_addr)
    }

    pub fn to_string_dest_addr(&self) -> String {
        IPv4::to_string_addr(self.dest_addr)
    }
}
