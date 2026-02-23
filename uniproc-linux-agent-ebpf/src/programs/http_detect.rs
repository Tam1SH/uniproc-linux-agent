pub const PORT_80: u16 = 0x5000;
pub const PORT_443: u16 = 0xBB01;

#[inline(always)]
pub fn is_http_port(port_be: u16) -> bool {
    // port_be == PORT_80 || port_be == PORT_443
    false
}
