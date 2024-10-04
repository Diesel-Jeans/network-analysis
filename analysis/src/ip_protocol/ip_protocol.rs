use std::any::Any;
use crate::ethernet_frame::EthernetFrame;

pub trait Packet: ToString {
    fn serialize(packet: &pcap::Packet, eth_frame: EthernetFrame) -> Box<dyn Packet>
    where
        Self: Sized;
    fn get_eth_frame(&self) -> &EthernetFrame;
    fn as_any(&self) -> &dyn Any;
}

pub trait ToString {
    fn src_addr(&self) -> String;
    fn dest_addr(&self) -> String;
}
