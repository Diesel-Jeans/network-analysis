use std::any::Any;

use crate::ethernet_frame::EthernetFrame;

pub trait Packet {
    fn serialize(packet: &pcap::Packet, eth_frame: EthernetFrame) -> Box<dyn Packet>
    where
        Self: Sized;

    #[allow(dead_code)]
    fn get_eth_frame(&self) -> &EthernetFrame;
    fn as_any(&self) -> &dyn Any;
}
