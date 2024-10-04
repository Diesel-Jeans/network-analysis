use super::ip_protocol;
use crate::ethernet_frame::{self, EthernetFrame};

pub struct IPv6 {
    pub eth_frame: EthernetFrame,
    pub src_addr: [u8; 16],
    pub dest_addr: [u8; 16],
}

impl IPv6 {
    fn to_string_addr(addr: [u8; 16]) -> String {
        unimplemented!();
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

impl ip_protocol::Packet for IPv6 {
    fn serialize(
        _packet: &pcap::Packet,
        eth_frame: ethernet_frame::EthernetFrame,
    ) -> Box<dyn ip_protocol::Packet> {
        Box::new(IPv6 {
            eth_frame,
            src_addr: unimplemented!(),
            dest_addr: unimplemented!(),
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
