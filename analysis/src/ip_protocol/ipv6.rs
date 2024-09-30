use super::ip_protocol;
use crate::ethernet_frame::EthernetFrame;

pub struct IPv6<'a> {
    pub eth_frame: &'a EthernetFrame,
    pub src_addr: [u8; 16],
    pub dest_addr: [u8; 16],
}

impl IPv6<'_> {
    fn to_string_addr(addr: [u8; 16]) -> String {
        unimplemented!();
    }
}

impl ip_protocol::ToString for IPv6<'_> {
    fn dest_addr(&self) -> String {
        IPv6::to_string_addr(self.dest_addr)
    }

    fn src_addr(&self) -> String {
        IPv6::to_string_addr(self.src_addr)
    }
}

impl<'a> ip_protocol::Packet<'a> for IPv6<'a> {
    fn create(
        _packet: &pcap::Packet,
        eth_frame: &'a crate::ethernet_frame::EthernetFrame,
    ) -> Box<IPv6<'a>> {
        Box::new(IPv6 {
            eth_frame,
            src_addr: unimplemented!(),
            dest_addr: unimplemented!(),
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }
}
