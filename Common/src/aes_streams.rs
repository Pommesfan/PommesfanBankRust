use std::io::{Read, Write, Result};
use crate::utils::{create_decryptor, create_encryptor, int_to_u8, u8_to_int};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, block_padding::ZeroPadding};

pub struct AesInputStream<'a, const BUFFERSIZE: usize> {
    readable: Box<dyn Read + 'a>,
    key: &'a [u8; 32],
    buf: [u8; BUFFERSIZE],
    buf_position: usize,
    reload: bool,
    received_size: usize,
}

pub struct AesOutputStream<'a, const BUFFERSIZE: usize> {
    writable: Box<dyn Write + 'a>,
    key: &'a [u8; 32],
    buf: [u8; BUFFERSIZE],
    buf_position: usize
}

impl<'a, const BUFFERSIZE: usize> AesInputStream<'a, BUFFERSIZE> {
    pub fn new(readable: impl Read + 'a, key: &'a [u8; 32]) -> AesInputStream<'a, BUFFERSIZE> {
        AesInputStream { readable: Box::new(readable), key: key, buf: [0; BUFFERSIZE], buf_position: 0, reload: true, received_size: 0 }
    }

    pub fn read_int(&mut self) -> i32 {
        let mut n: [u8; 4] = [0; 4];
        let _ = self.read(&mut n);
        u8_to_int(n)
    }

    pub fn read_string(&mut self) -> String {
        let len = self.read_int();
        let b = self.read_to_vec(len as usize);
        unsafe {
            String::from_utf8_unchecked(b)
        }
    }

    pub fn read_to_vec(&mut self, size_to_receive: usize) -> Vec<u8> {
        let mut res = Vec::with_capacity(size_to_receive);
        let strategy = ReadToVector{v: &mut res};
        let _ = self.read_with_strategy(strategy);
        res
    }

    fn read_with_strategy(&mut self, mut strategy: impl ReadStrategy) -> Result<usize> {
        if self.reload {
            self.from_readable()?;
        }

        if self.received_size == 0 {
            return Ok(0);
        }

        let mut b_position: usize = 0;
        let size_to_receive = strategy.len();
        while b_position < size_to_receive {
            let buf_remaining = self.received_size - self.buf_position;
            let b_remaining = size_to_receive - b_position;

            if b_remaining < buf_remaining {
                strategy.add(&mut self.buf[self.buf_position .. self.buf_position + b_remaining], b_position);
                b_position += b_remaining;
                self.buf_position += b_remaining;
            } else if b_remaining == buf_remaining {
                strategy.add(&mut self.buf[self.buf_position .. self.buf_position + b_remaining], b_position);
                b_position += b_remaining;
                self.reload = true;
            } else {
                strategy.add(&mut self.buf[self.buf_position .. self.buf_position + buf_remaining], b_position);
                self.from_readable()?;
                b_position += buf_remaining;
                if self.received_size == 0 {
                    return Ok(b_position);
                }
            }
        }
        Ok(b_position)
    }

    fn from_readable(&mut self) -> Result<()> {
        self.buf_position = 0;
        self.reload = false;
        self.received_size = self.readable.read(&mut self.buf)?;
        let _ = create_decryptor(self.key).decrypt_padded_mut::<ZeroPadding>(&mut self.buf);
        Ok(())
    }
}

impl<'a, const BUFFERSIZE: usize> Read for AesInputStream<'a, BUFFERSIZE> {
    fn read(&mut self, data: &mut [u8]) -> Result<usize> {
        let strategy = ReadToSlice {s: data};
        self.read_with_strategy(strategy)
    }
}

impl<'a, const BUFFERSIZE: usize> AesOutputStream<'a, BUFFERSIZE> {
    pub fn new(writable: impl Write + 'a, key: &'a [u8; 32]) -> AesOutputStream<'a, BUFFERSIZE> {
        AesOutputStream { writable: Box::new(writable), key: key, buf: [0; BUFFERSIZE], buf_position: 0 }
    }

    pub fn write_int(&mut self, i: i32) -> Result<()> {
        self.write(&int_to_u8(i))?;
        Ok(())
    }

    pub fn write_string(&mut self, s: &String) -> Result<()> {
        let b = s.as_bytes();
        self.write_int(b.len() as i32)?;
        self.write(b)?;
        Ok(())
    }
    
    fn to_writable(&mut self, is_full: bool) -> Result<usize> {
        let len = if is_full {
            (&self.buf).len()
        } else {
            let rest = self.buf_position % 16;
            if rest != 0 {
                self.buf_position + 16 - rest
            } else {
                self.buf_position
            }
        };
        let _ = create_encryptor(self.key).encrypt_padded_mut::<ZeroPadding>(&mut self.buf, len);
        let res = self.writable.write(&mut self.buf[0..len]);
        self.buf_position = 0;
        res
    }
}

impl<'a, const BUFFERSIZE: usize> Write for AesOutputStream<'a, BUFFERSIZE> {
    fn write(&mut self, b: &[u8]) -> Result<usize> {
        let buf_len = self.buf.len();
        let mut start = 0;
        while start < b.len() {
            let end = if b.len() - start > buf_len  {
                start + buf_len
            } else {
                b.len()
            };

            let chunk_len = end - start;
            let remaining_size = buf_len - self.buf_position;

            if remaining_size > chunk_len {
                self.buf[self.buf_position .. self.buf_position + chunk_len].copy_from_slice(&b[start .. start + chunk_len]);
                self.buf_position += chunk_len;
                start += chunk_len;
            } else if remaining_size == chunk_len {
                self.buf[self.buf_position .. self.buf_position + chunk_len].copy_from_slice(&b[start .. start + chunk_len]);
                self.to_writable(true)?;
                start += chunk_len;
            } else {
                self.buf[self.buf_position .. buf_len].copy_from_slice(&b[start .. start + remaining_size]);
                self.to_writable(true)?;
                start += remaining_size;
            }
        }
        Ok(start)
    }

    fn flush(&mut self) -> Result<()>{
        self.to_writable(false)?;
        self.writable.flush()?;
        Ok(())
    }
}

impl<'a, const BUFFERSIZE: usize> Drop for AesOutputStream<'a, BUFFERSIZE> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

trait ReadStrategy {
    fn add(&mut self, data: &[u8], start: usize);
    fn len(&mut self) -> usize;
}

struct ReadToVector<'a> {
    v: &'a mut Vec<u8>
}

impl<'a> ReadStrategy for ReadToVector<'a> {
    fn add(&mut self, data: &[u8], _start: usize) {
        let _ = self.v.write(&data);
    }
    
    fn len(&mut self) -> usize {
        self.v.capacity()
    }
}

struct ReadToSlice<'a> {
    s: &'a mut [u8],
}

impl<'a> ReadStrategy for ReadToSlice<'a> {
    fn add(&mut self, data: &[u8], start: usize) {
        let len = data.len();
        self.s[start .. start + len].copy_from_slice(data);
    }
    
    fn len(&mut self) -> usize {
        self.s.len()
    }
}