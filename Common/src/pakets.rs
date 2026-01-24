use std::io::Read;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use bytebuffer::ByteBuffer;
use aes::cipher::block_padding::ZeroPadding;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

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

    pub fn get_paket(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    fn fill_until_mod_16(&mut self) {
        let rest = self.get_len() % 16;
        if rest != 0 {
            for _i in 0 .. 16 - rest {
                self.buf.write_u8(0);
            }
        }
    }

    pub fn get_len(&self) -> usize {
        return self.buf.len()
    }

    pub fn get_encrypted(&mut self, aes_enc: &Aes256CbcEnc) -> Vec<u8> {
        self.fill_until_mod_16();
        let to_encrypt = self.get_paket();
        let mut res = Vec::with_capacity(to_encrypt.len());
        for i in 0 .. to_encrypt.len() / 16 {
            let mut chunk: [u8; 16] = [0; 16];
            chunk.copy_from_slice(&to_encrypt[i .. i + 16]);
            let _ = aes_enc.clone().encrypt_padded_mut::<ZeroPadding>(&mut chunk, 16);
            res.append(&mut chunk.to_vec());
        }
        res
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

    pub fn from_encrypted(data: &[u8], aes_dec: &Aes256CbcDec) -> PaketReader {
        let mut res: Vec<u8> = Vec::with_capacity(data.len());
        for i in 0 .. data.len() / 16 {
            let mut chunk: [u8; 16] = [0; 16];
            chunk.copy_from_slice(&data[i .. i + 16]);
            let _ = aes_dec.clone().decrypt_padded_mut::<ZeroPadding>(&mut chunk);
            res.append(&mut chunk.to_vec());
        }
        PaketReader::new(&res)
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