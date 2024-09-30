//use ethernet_frame::{EtherType, EthernetFrame};
use crate::ethernet_frame::EthernetFrame;

pub trait ToString {
    fn src_addr(&self) -> String;
    fn dest_addr(&self) -> String;
}

pub trait Packet<'a>: ToString {
    fn create(packet: &pcap::Packet, eth_frame: &'a EthernetFrame) -> Box<Self>
    where
        Self: Sized;
    fn get_eth_frame(&self) -> &EthernetFrame;
}
