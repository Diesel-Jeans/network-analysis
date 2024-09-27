pub trait ToString {
    fn src_addr(&self) -> String;
    fn dest_addr(&self) -> String;
}