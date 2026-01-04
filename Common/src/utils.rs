use bytebuffer::ByteBuffer;
use sha2::{Sha256, Digest};
use random_string::generate;

pub const START_LOGIN: i32 = 0;
pub const COMPLETE_LOGIN:i32 = 1;
pub const EXIT_COMMAND:i32 = 2;
pub const BANKING_COMMAND:i32 = 3;
pub const SHOW_BALANCE_COMMAND: i32 = 4;
pub const TRANSFER_COMMAND:i32 = 5;
pub const SEE_TURNOVER:i32 = 6;
pub const SHOW_BALANCE_RESPONSE: i32 = 7;
pub const SEE_TURNOVER_RESPONSE:i32 = 9;
pub const LOGIN_ACK:i32 = 5687789;
pub const LOGIN_NACK:i32 = 129836;
pub const TERMINATION:i32 = 2147483647;

pub const MANUAL_TRANSFER: i32 = 1;

pub const SERVER_IP: &str = "127.0.0.1";
pub const UDP_PORT: i32 = 10000;
pub const FIRST_TCP_PORT: i32 = 12000;

pub const IV: [u8; 16] = [102, 104, 115, 56, 100, 57, 102, 103, 56, 52, 53, 106, 115, 107, 100, 54];
pub const DATE_FORMAT: &str = "%Y-%m-%d";
pub const AES_STREAMS_BUFFER_SIZE: usize = 1024;

pub fn create_udp_url() -> String {
    create_url(UDP_PORT)
}

pub fn create_tcp_url(idx: i32) -> String {
    create_url(FIRST_TCP_PORT + idx)
}

pub fn create_url(port: i32) -> String {
    let mut res = String::new();
    res.push_str(SERVER_IP);
    res.push_str(":");
    res.push_str(&port.to_string());
    res
}

pub fn create_hashcode_sha256(s: &String) -> [u8; 32] {
    let b =  s.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b);
    let b = hasher.finalize();
    let mut b_owned: [u8; 32] = [0; 32];
    b_owned[..b.len()].copy_from_slice(&b);
    b_owned
}

pub fn create_random_id(n: i32) -> String {
    let charset = "1234567890";
    return generate(n as usize, charset);
}

pub fn int_to_u8(i: i32) -> Vec<u8> {
    let mut b = ByteBuffer::new();
    b.write_i32(i);
    b.into_vec()
}

pub fn u8_to_int(b: &[u8]) -> i32 {
    let mut b = ByteBuffer::from_bytes(b);
    b.read_i32().unwrap()
}

pub fn string_to_u8(s: String) -> [u8; 16] {
    let mut a: [u8; 16] = [0; 16];
    a[..16].copy_from_slice(s.as_bytes());
    a
}