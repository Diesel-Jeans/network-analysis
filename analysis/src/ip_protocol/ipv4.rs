use super::ip_protocol;
use crate::ethernet_frame;
use ethernet_frame::EthernetFrame;

pub struct IPv4<'a> {
    pub eth_frame: &'a EthernetFrame,
    pub src_addr: [u8; 4],
    pub dest_addr: [u8; 4],
}

impl IPv4<'_> {
    fn to_string_addr(addr: [u8; 4]) -> String {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

impl ip_protocol::ToString for IPv4<'_> {
    fn src_addr(&self) -> String {
        IPv4::to_string_addr(self.src_addr)
    }

    fn dest_addr(&self) -> String {
        IPv4::to_string_addr(self.dest_addr)
    }
}

impl<'a> ip_protocol::Packet<'a> for IPv4<'a> {
    fn create(
        packet: &pcap::Packet,
        eth_frame: &'a ethernet_frame::EthernetFrame,
    ) -> Box<IPv4<'a>> {
        Box::new(IPv4 {
            eth_frame,
            src_addr: [packet[30], packet[31], packet[32], packet[33]],
            dest_addr: [packet[34], packet[35], packet[33], packet[34]],
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }
}
