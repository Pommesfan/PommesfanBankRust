use std::{io::{Read, Write}, net::TcpStream};
use crate::utils::{int_to_u8, u8_to_int};
use aes::cipher::block_padding::ZeroPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub struct AesInputStream<const BUFFERSIZE: usize> {
    stream: TcpStream,
    aes_dec: Aes256CbcDec,
    buf: [u8; BUFFERSIZE],
    buf_position: usize,
    reload: bool,
    received_size: usize,
}

pub struct AesOutputStream<const BUFFERSIZE: usize> {
    stream: TcpStream,
    aes_enc: Aes256CbcEnc,
    buf: [u8; BUFFERSIZE],
    buf_position: usize
}

impl<const BUFFERSIZE: usize> AesInputStream<BUFFERSIZE> {
    pub fn new(stream: TcpStream, dec: Aes256CbcDec) -> AesInputStream<BUFFERSIZE> {
        AesInputStream { stream: stream, aes_dec: dec, buf: [0; BUFFERSIZE], buf_position: 0, reload: true, received_size: 0 }
    }

    pub fn read_int(&mut self) -> i32 {
        let b = self.read(4);
        u8_to_int(&b)
    }

    pub fn read_string(&mut self) -> String {
        let len = self.read_int();
        let b = self.read(len as usize);
        unsafe {
            String::from_utf8_unchecked(b)
        }
    }

    pub fn read(&mut self, size_to_receive: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(size_to_receive);
        if self.reload {
            self.from_stream()
        }

        if self.received_size == 0 {
            return v;
        }

        let mut b_position: usize = 0;
        while b_position < size_to_receive {
            let buf_remaining = self.received_size - self.buf_position;
            let b_remaining = size_to_receive - b_position;

            if b_remaining < buf_remaining {
                v.append(&mut self.buf[self.buf_position .. self.buf_position + b_remaining].to_vec());
                b_position += b_remaining;
                self.buf_position += b_remaining;
            } else if b_remaining == buf_remaining {
                v.append(&mut self.buf[self.buf_position .. self.buf_position + b_remaining].to_vec());
                b_position += b_remaining;
                self.reload = true;
            } else {
                v.append(&mut self.buf[self.buf_position .. self.buf_position + buf_remaining].to_vec());
                self.from_stream();
                if self.received_size == usize::MAX {
                    return v;
                }
                b_position += buf_remaining;
            }
        }
        v
    }

    fn from_stream(&mut self) {
        self.buf_position = 0;
        self.reload = false;
        self.received_size = self.stream.read(&mut self.buf).unwrap();
        let _ = self.aes_dec.clone().decrypt_padded_mut::<ZeroPadding>(&mut self.buf);
    }
}

impl<const BUFFERSIZE: usize> AesOutputStream<BUFFERSIZE> {
    pub fn new(stream: TcpStream, enc: Aes256CbcEnc) -> AesOutputStream<BUFFERSIZE> {
        AesOutputStream { stream: stream, aes_enc: enc, buf: [0; BUFFERSIZE], buf_position: 0 }
    }

    pub fn write_int(&mut self, i: i32) {
        let _ = self.write(&int_to_u8(i));
    }

    pub fn write_string(&mut self, s: &String) {
        let b = s.as_bytes();
        self.write_int(b.len() as i32);
        self.write(b);
    }

    pub fn write(&mut self, b: &[u8]) {
        let buf_len = self.buf.len();
        let mut start = 0;
        while start < b.len() {
            let end;
            if b.len() - start > buf_len  {
                end = start + buf_len;
            } else {
                end = b.len();
            }

            let chunk_len = end - start;
            let remaining_size = buf_len - self.buf_position;

            if remaining_size > chunk_len {
                self.buf[self.buf_position .. self.buf_position + chunk_len].copy_from_slice(&b[start .. start + chunk_len]);
                self.buf_position += chunk_len;
                start += chunk_len;
            } else if remaining_size == chunk_len {
                self.buf[self.buf_position .. self.buf_position + chunk_len].copy_from_slice(&b[start .. start + chunk_len]);
                self.to_stream();
                start += chunk_len;
            } else {
                let overflow_pos = start + remaining_size;
                self.buf[self.buf_position .. self.buf_position + overflow_pos].copy_from_slice(&b[start .. start + overflow_pos]);
                self.to_stream();
                let len = chunk_len - overflow_pos;
                self.buf[self.buf_position .. self.buf_position + len].copy_from_slice(&b[overflow_pos .. overflow_pos + len]);
                start += overflow_pos;
            }
        }
    }
    
    fn to_stream(&mut self) {
        let len = (&self.buf).len();
        let _ = self.aes_enc.clone().encrypt_padded_mut::<ZeroPadding>(&mut self.buf, len);
        let _ = self.stream.write(&self.buf);
        self.buf_position = 0;
    }

    pub fn flush(&mut self) {
        self.to_stream();
        let _ = self.stream.flush();
    }
}