use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use bytes::{BufMut, Bytes, BytesMut};
use crate::utils::{to_fixed_len, u8_to_int, create_encryptor, create_decryptor};

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

    fn fill_until_mod_16(&mut self, start: usize) {
        let rest = (self.get_len() - start) % 16;
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

    pub fn encrypt(&mut self, key: &[u8; 32], start: usize) {
        self.fill_until_mod_16(start);
        let mut aes_enc = create_encryptor(key);
        let sub_buf = &mut self.buf[start .. ];
        for i in 0 .. sub_buf.len() / 16 {
            let mut chunk: [u8; 16] = [0; 16];
            let start = i * 16;
            let end = start + 16;
            chunk.copy_from_slice(&sub_buf[start .. end]);
            let mut chunk_gen = chunk.into();
            let _ = aes_enc.encrypt_block_mut(&mut chunk_gen);
            sub_buf[start .. end].copy_from_slice(&chunk_gen);
        }
    }
}

pub struct PaketReader<'a> {
    data: &'a mut [u8],
    buf_position: usize
}

impl<'a> PaketReader<'a> {
    pub fn new(data: &mut [u8]) -> PaketReader {
        PaketReader {
            data,
            buf_position: 0
        }
    }

    pub fn from_encrypted(data: &'a mut [u8], key: &[u8; 32]) -> PaketReader<'a> {
        let mut aes_dec = create_decryptor(key);
        for i in 0 .. data.len() / 16 {
            let mut chunk: [u8; 16] = [0; 16];
            let start = i * 16;
            let end = start + 16;
            chunk.copy_from_slice(&data[start .. end]);
            let mut chunk_gen = chunk.into();
            let _ = aes_dec.decrypt_block_mut(&mut chunk_gen);
            data[start .. end].copy_from_slice(&chunk_gen);
        }
        PaketReader::new(data)
    }

    pub fn get_int(&mut self) -> i32 {
        u8_to_int(self.get_bytes_fixed::<4>())
    }

    pub fn get_bytes(&mut self, size: usize) -> &[u8] {
        let end = self.buf_position + size;
        let res = &self.data[self.buf_position .. end];
        self.buf_position = end;
        res
    }

    pub fn get_bytes_fixed<const COUNT: usize>(&mut self) -> [u8; COUNT] {
        to_fixed_len::<COUNT>(self.get_bytes(COUNT))
    }

    pub fn get_last_bytes(&mut self) -> &mut [u8] {
        &mut self.data[self.buf_position .. ]
    }

    pub fn get_slice(&mut self) -> &[u8] {
        let len = (*self).get_int() as usize;
        self.get_bytes(len)
    }

    pub fn get_string_with_len(&mut self, len: usize) -> String {
        unsafe {
            String::from_utf8_unchecked(self.get_bytes(len).to_vec())
        }
    }

    pub fn get_string(&mut self) -> String {
        unsafe {
            String::from_utf8_unchecked(self.get_slice().to_vec())
        }
    }
}