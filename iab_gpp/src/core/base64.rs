use std::io;
use std::io::Read;
use thiserror::Error;

/// The error type that describes failures to decode Base64 encoded strings.
#[derive(Error, Debug)]
pub enum DecodeError {
    /// An invalid byte was found in the input. The offset and offending byte are provided.
    #[error("invalid byte {1} at offset {0}")]
    InvalidByte(usize, u8),
}

pub struct Base64SliceReader<'a> {
    input: &'a [u8],
    input_pos: usize,
    acc: u32,
    bits: u8,
}

impl<'a> Base64SliceReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            input_pos: 0,
            acc: 0,
            bits: 0,
        }
    }
}

impl Read for Base64SliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut written = 0usize;

        while written < buf.len() {
            while self.bits < 8 && self.input_pos < self.input.len() {
                let byte = self.input[self.input_pos];
                self.input_pos += 1;
                let value = base64_value(byte).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        DecodeError::InvalidByte(self.input_pos - 1, byte),
                    )
                })? as u32;
                self.acc = (self.acc << 6) | value;
                self.bits += 6;
            }

            if self.bits >= 8 {
                self.bits -= 8;
                buf[written] = ((self.acc >> self.bits) & 0xFF) as u8;
                self.acc &= (1u32 << self.bits) - 1;
                written += 1;
                continue;
            }

            if self.input_pos == self.input.len() && self.bits > 0 {
                buf[written] = (self.acc << (8 - self.bits)) as u8;
                self.acc = 0;
                self.bits = 0;
                written += 1;
            }

            break;
        }

        Ok(written)
    }
}

const INVALID_B64_VALUE: i8 = -1;

const BASE64_DECODE_TABLE: [i8; 256] = make_base64_decode_table();

const fn make_base64_decode_table() -> [i8; 256] {
    let mut table = [INVALID_B64_VALUE; 256];

    let mut i = 0usize;
    while i < 26 {
        table[b'A' as usize + i] = i as i8;
        table[b'a' as usize + i] = (i + 26) as i8;
        i += 1;
    }

    i = 0;
    while i < 10 {
        table[b'0' as usize + i] = (i + 52) as i8;
        i += 1;
    }

    table[b'-' as usize] = 62;
    table[b'_' as usize] = 63;

    table
}

#[inline]
fn base64_value(b: u8) -> Option<u8> {
    let v = BASE64_DECODE_TABLE[b as usize];
    if v >= 0 {
        Some(v as u8)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(b'A' => Some(0))]
    #[test_case(b'Z' => Some(25))]
    #[test_case(b'a' => Some(26))]
    #[test_case(b'z' => Some(51))]
    #[test_case(b'0' => Some(52))]
    #[test_case(b'9' => Some(61))]
    #[test_case(b'=' => None ; "equal")]
    #[test_case(b'#' => None ; "sharp")]
    fn base64_value_map(b: u8) -> Option<u8> {
        base64_value(b)
    }

    #[test_case("DBABM" => vec![12, 16, 1, 48] ; "simple header")]
    #[test_case("" => is empty ; "empty string")]
    fn test_base64_reader(s: &str) -> Vec<u8> {
        let mut r = Base64SliceReader::new(s.as_bytes());
        let mut buf = vec![0; 32];
        let n = r.read(&mut buf).unwrap();
        buf.truncate(n);

        buf
    }

    #[test_case("===" => matches DecodeError::InvalidByte(0, b'=') ; "equal signs")]
    #[test_case("a  " => matches DecodeError::InvalidByte(1, b' ') ; "whitespaces")]
    fn test_base64_reader_error(s: &str) -> DecodeError {
        let mut r = Base64SliceReader::new(s.as_bytes());
        let mut buf = vec![0; 32];
        r.read(&mut buf).unwrap_err().downcast().unwrap()
    }
}
