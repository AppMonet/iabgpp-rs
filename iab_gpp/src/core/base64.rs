use bitstream_io::{
    BitCount, BitRead, Endianness, Primitive, SignedBitCount, SignedInteger, UnsignedInteger,
};
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

pub struct Base64BitReader<'a> {
    reader: Base64SliceReader<'a>,
    value: u8,
    bits: u32,
}

impl<'a> Base64BitReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            reader: Base64SliceReader::new(input),
            value: 0,
            bits: 0,
        }
    }

    #[inline(always)]
    fn read_decoded_byte(&mut self) -> io::Result<u8> {
        let mut byte = [0u8; 1];
        let read = self.reader.read(&mut byte)?;
        if read == 1 {
            Ok(byte[0])
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        }
    }

    #[inline(always)]
    fn trim_queue(&mut self) {
        if self.bits == 0 {
            self.value = 0;
        } else {
            self.value &= (1u8 << self.bits) - 1;
        }
    }
}

impl BitRead for Base64BitReader<'_> {
    #[inline(always)]
    fn read_bit(&mut self) -> io::Result<bool> {
        if self.bits == 0 {
            self.value = self.read_decoded_byte()?;
            self.bits = 8;
        }

        self.bits -= 1;
        let bit = (self.value >> self.bits) & 1;
        self.trim_queue();
        Ok(bit == 1)
    }

    #[inline(always)]
    fn read_unsigned_counted<const MAX: u32, U>(&mut self, bits: BitCount<MAX>) -> io::Result<U>
    where
        U: UnsignedInteger,
    {
        let mut remaining = u32::from(bits);
        if remaining > U::BITS_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "excessive bits for type read",
            ));
        }

        let mut value = U::ZERO;
        while remaining > 0 {
            if self.bits == 0 {
                self.value = self.read_decoded_byte()?;
                self.bits = 8;
            }

            let take = remaining.min(self.bits);
            let shift = self.bits - take;
            let mask = if take == 8 {
                u8::MAX
            } else {
                ((1u16 << take) - 1) as u8
            };
            let chunk = (self.value >> shift) & mask;

            value = value.shl_default(take) | U::from_u8(chunk);
            self.bits -= take;
            self.trim_queue();
            remaining -= take;
        }

        Ok(value)
    }

    #[inline(always)]
    fn read_signed_counted<const MAX: u32, S>(
        &mut self,
        bits: impl TryInto<SignedBitCount<MAX>>,
    ) -> io::Result<S>
    where
        S: SignedInteger,
    {
        let bits = bits.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "signed reads need at least 1 bit for sign",
            )
        })?;
        let bits_u32 = u32::from(bits);
        if bits_u32 > S::BITS_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "excessive bits for type read",
            ));
        }

        let sign = self.read_bit()?;
        let unsigned_bits = bits_u32 - 1;
        let unsigned = self.read_unsigned_var::<S::Unsigned>(unsigned_bits)?;

        Ok(if sign {
            unsigned.as_negative(bits_u32)
        } else {
            unsigned.as_non_negative()
        })
    }

    #[inline(always)]
    fn read_to<V>(&mut self) -> io::Result<V>
    where
        V: Primitive,
    {
        let mut buf = V::buffer();
        self.read_bytes(buf.as_mut())?;
        Ok(V::from_be_bytes(buf))
    }

    #[inline(always)]
    fn read_as_to<F, V>(&mut self) -> io::Result<V>
    where
        F: Endianness,
        V: Primitive,
    {
        let mut buf = V::buffer();
        self.read_bytes(buf.as_mut())?;
        let f = core::any::type_name::<F>();
        if f.contains("LittleEndian") {
            Ok(V::from_le_bytes(buf))
        } else {
            Ok(V::from_be_bytes(buf))
        }
    }

    #[inline(always)]
    fn skip(&mut self, mut bits: u32) -> io::Result<()> {
        if bits == 0 {
            return Ok(());
        }

        if self.bits > 0 {
            let take = bits.min(self.bits);
            self.bits -= take;
            self.trim_queue();
            bits -= take;
        }

        while bits >= 8 {
            let _ = self.read_decoded_byte()?;
            bits -= 8;
        }

        if bits > 0 {
            self.value = self.read_decoded_byte()?;
            self.bits = 8 - bits;
            self.trim_queue();
        }

        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if self.bits == 0 {
            self.reader.read_exact(buf)
        } else {
            for b in buf.iter_mut() {
                *b = self.read_unsigned::<8, u8>()?;
            }
            Ok(())
        }
    }

    #[inline(always)]
    fn byte_aligned(&self) -> bool {
        self.bits == 0
    }

    #[inline(always)]
    fn byte_align(&mut self) {
        self.value = 0;
        self.bits = 0;
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
