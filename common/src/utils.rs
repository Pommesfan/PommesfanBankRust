use bytebuffer::ByteBuffer;
use sha2::{Sha256, Digest};
use random_string::generate;

pub const LOGIN_ACK:i32 = 5687789;

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