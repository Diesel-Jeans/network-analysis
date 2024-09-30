#[derive(Clone, Copy)]
pub enum EtherType {
    IPv4,
    IPv6,
}

impl Default for EtherType {
    fn default() -> Self {
        EtherType::IPv4
    }
}

impl EtherType {
    fn set_type(hex: &str) -> EtherType {
        match hex {
            "0x0800" => EtherType::IPv4,
            "0x86DD" => EtherType::IPv6,
            _ => todo!(),
        }
    }

    fn value(&self) -> String {
        match *self {
            EtherType::IPv4 => "0x0800".to_string(),
            EtherType::IPv6 => "0x86DD".to_string(),
        }
    }

    pub fn to_string(&self) -> String {
        format!("{}", self.value())
    }
}

pub struct EthernetFrame {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ip_type: EtherType,
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
        format!("{}", self.ip_type.to_string())
    }

    pub fn create(packet: &pcap::Packet) -> EthernetFrame {
        EthernetFrame {
            dest_mac: [
                packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
            ],
            src_mac: [
                packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
            ],
            ip_type: EtherType::set_type(&format!(
                "0x{:04x}",
                u16::from_be_bytes([packet[12], packet[13]])
            )),
        }
    }
}
