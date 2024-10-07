use std::any::Any;

// use pcap::Packet;
use crate::ethernet_frame::EthernetFrame;

pub trait Packet {
    fn serialize(packet: &pcap::Packet, eth_frame: EthernetFrame) -> Box<dyn Packet>
    where
        Self: Sized;
    fn get_eth_frame(&self) -> &EthernetFrame;
    fn as_any(&self) -> &dyn Any;
}

