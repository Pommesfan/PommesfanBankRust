use std::io::{Read, Write};

use bytebuffer::ByteBuffer;

pub struct PaketBuilder {
    buf: ByteBuffer,
}

impl PaketBuilder {
    pub fn new() -> PaketBuilder {
        PaketBuilder {
            buf: ByteBuffer::new(),
        }
    }

    pub fn add_int(&mut self, n: i32) {
        self.buf.write_i32(n);
    }

    pub fn add_bytes(&mut self, b: &[u8]) {
        self.buf.write_bytes(b);
    }

    pub fn add_slice(&mut self, b: &[u8]) {
        self.add_int(b.len().try_into().unwrap());
        self.add_bytes(b);
    }

    pub fn add_string(&mut self, s: String) {
        self.add_slice(s.as_bytes());
    }

    pub fn get_paket(&self) -> &[u8]{
        self.buf.as_bytes()
    }
}

pub struct PaketReader {
    buf: ByteBuffer
}

impl PaketReader {
    pub fn new(data: &[u8]) -> PaketReader {
        PaketReader {
            buf: ByteBuffer::from_bytes(data),
        }
    }

    pub fn get_int(&mut self) -> i32 {
        self.buf.read_i32().unwrap()
    }

    pub fn get_bytes(&mut self, size: usize) -> Vec<u8> {
        self.buf.read_bytes(size).unwrap()
    }

    pub fn get_slice(&mut self) -> Vec<u8>{
        let len = (*self).get_int() as usize;
        self.get_bytes(len)
    }

    pub fn get_string(&mut self) -> String {
        unsafe {
            String::from_utf8_unchecked(self.get_slice())
        }
    }
}