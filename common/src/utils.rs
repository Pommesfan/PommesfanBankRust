use bytebuffer::ByteBuffer;
use sha2::{Sha256, Digest};
use random_string::generate;

pub const START_LOGIN: i32 = 0;
pub const COMPLETE_LOGIN: i32 = 1;
pub const LOGIN_ACK:i32 = 5687789;
pub const IV: [u8; 16] = [102, 104, 115, 56, 100, 57, 102, 103, 56, 52, 53, 106, 115, 107, 100, 54];

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

pub fn string_to_u8(s: String) -> [u8; 16] {
    let mut a: [u8; 16] = [0; 16];
    a[..16].copy_from_slice(s.as_bytes());
    a
}