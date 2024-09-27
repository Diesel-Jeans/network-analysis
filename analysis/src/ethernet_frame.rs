#[derive(Default)]
pub struct EthernetFrame {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ip_type: u16,
}

impl EthernetFrame {
    fn to_string_mac(mac: [u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    pub fn to_string_dest_mac(&self) -> String {
        EthernetFrame::to_string_mac(self.dest_mac)
    }

    pub fn to_string_src_mac(&self) -> String {
        EthernetFrame::to_string_mac(self.src_mac)
    }

    pub fn to_string_ip_type(&self) -> String {
        format!("0x{:04x}", self.ip_type)
    }
}
