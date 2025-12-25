use std::{io::{Read, Write}, net::TcpStream};
use crate::utils::{int_to_u8, u8_to_int};

pub struct SliceReader {
    stream: TcpStream
}

pub struct SliceWriter {
    stream: TcpStream
}

impl SliceReader {
    pub fn new(stream: TcpStream) -> SliceReader {
        SliceReader {
            stream: stream,
        }
    }

    pub fn read_int(&mut self) -> i32 {
        let mut b: [u8; 4] = [0; 4];
        let _ = self.stream.read(&mut b);
        u8_to_int(&b)
    }

    pub fn read_string<const COUNT: usize>(&mut self) -> String {
        // let size = self.read_int();
        let mut b  = [0; COUNT];
        let _ = self.stream.read(&mut b);
        unsafe {
            String::from_utf8_unchecked(b.to_vec())
        }
    }
}

impl SliceWriter {
    pub fn new(stream: TcpStream) -> SliceWriter {
        SliceWriter {
            stream: stream,
        }
    }

    pub fn write_int(&mut self, i: i32) {
        let _ = self.stream.write(&int_to_u8(i));
        let _ = self.stream.flush();
    }

    pub fn write_string(&mut self, s: &String) {
        let _ = self.stream.write(s.as_bytes());
        let _ = self.stream.flush();
    }
}