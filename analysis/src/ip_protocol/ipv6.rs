use libc::timeval;

use super::ip_protocol;
use crate::ethernet_frame::{self, EthernetFrame};

pub struct IPv6 {
    pub time_stamp: timeval,
    pub eth_frame: EthernetFrame,
    pub src_addr: [u8; 16],
    pub dest_addr: [u8; 16],
}

impl IPv6 {
    fn to_string_addr(addr: [u8; 16]) -> String {
        unimplemented!();
    }
}

impl ip_protocol::Packet for IPv6 {
    fn serialize(
        _packet: &pcap::Packet,
        eth_frame: ethernet_frame::EthernetFrame,
    ) -> Box<dyn ip_protocol::Packet> {
        Box::new(IPv6 {
            time_stamp: unimplemented!(),
            eth_frame,
            src_addr: unimplemented!(),
            dest_addr: unimplemented!(),
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }

    fn get_time_stamp(&self) -> timeval {
        self.time_stamp
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
