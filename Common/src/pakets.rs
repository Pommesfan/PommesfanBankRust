use std::io::Read;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use bytebuffer::ByteReader;
use aes::cipher::block_padding::ZeroPadding;
use bytes::{BufMut, Bytes, BytesMut};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct PaketBuilder {
    buf: BytesMut
}

impl PaketBuilder {
    pub fn new(capacity: usize) -> PaketBuilder {
        PaketBuilder {
            buf: BytesMut::with_capacity(capacity)
        }
    }

    pub fn add_int(&mut self, n: i32) {
        self.buf.put_i32(n);
    }

    pub fn add_bytes(&mut self, b: &[u8]) {
        self.buf.put(b);
    }

    pub fn add_slice(&mut self, b: &[u8]) {
        self.add_int(b.len().try_into().unwrap());
        self.add_bytes(b);
    }

    pub fn add_string(&mut self, s: String) {
        self.add_slice(s.as_bytes());
    }

    fn fill_until_mod_16(&mut self) {
        let rest = self.get_len() % 16;
        if rest != 0 {
            for _i in 0 .. 16 - rest {
                self.buf.put_u8(0);
            }
        }
    }

    pub fn get_len(&self) -> usize {
        return self.buf.len()
    }

    pub fn get_paket(&self) -> Bytes {
        Bytes::from(self.buf.clone())
    }

    pub fn get_encrypted(&mut self, aes_enc: &Aes256CbcEnc) -> Bytes {
        self.fill_until_mod_16();
        for i in 0 .. (&self.buf).len() / 16 {
            let mut chunk: [u8; 16] = [0; 16];
            let start = i * 16;
            chunk.copy_from_slice(&self.buf[start .. start + 16]);
            let _ = aes_enc.clone().encrypt_padded_mut::<ZeroPadding>(&mut chunk, 16);
            self.buf[start .. start + 16].copy_from_slice(&mut chunk.to_vec());
        }
        Bytes::from(self.buf.clone())
    }
}

pub struct PaketReader<'a> {
    buf: ByteReader<'a>
}

impl<'a> PaketReader<'a> {
    pub fn new(data: &[u8]) -> PaketReader {
        PaketReader {
            buf: ByteReader::from_bytes(data)
        }
    }

    pub fn from_encrypted(data: &'a mut [u8], aes_dec: &'a Aes256CbcDec) -> PaketReader<'a> {
        for i in 0 .. data.len() / 16 {
            let mut chunk: [u8; 16] = [0; 16];
            let start = i * 16;
            chunk.copy_from_slice(&data[start .. start + 16]);
            let _ = aes_dec.clone().decrypt_padded_mut::<ZeroPadding>(&mut chunk);
            data[start .. start + 16].copy_from_slice(&chunk);
        }
        PaketReader::new(data)
    }

    pub fn get_int(&mut self) -> i32 {
        self.buf.read_i32().unwrap()
    }

    pub fn get_bytes(&mut self, size: usize) -> Vec<u8> {
        self.buf.read_bytes(size).unwrap()
    }

    pub fn get_last_bytes(&mut self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1024);
        self.buf.read_to_end(&mut b).unwrap();
        b
    }

    pub fn get_slice(&mut self) -> Vec<u8>{
        let len = (*self).get_int() as usize;
        self.get_bytes(len)
    }

    pub fn get_string_with_len(&mut self, len: usize) -> String {
        unsafe {
            String::from_utf8_unchecked(self.get_bytes(len))
        }
    }

    pub fn get_string(&mut self) -> String {
        unsafe {
            String::from_utf8_unchecked(self.get_slice())
        }
    }
}