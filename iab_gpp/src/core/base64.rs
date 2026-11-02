use bitstream_io::{
    BitCount, BitRead, Endianness, Primitive, SignedBitCount, SignedInteger, UnsignedInteger,
};
use std::io;
#[cfg(test)]
use std::io::Read;
use thiserror::Error;

/// The error type that describes failures to decode Base64 encoded strings.
#[derive(Error, Debug)]
pub enum DecodeError {
    /// An invalid byte was found in the input. The offset and offending byte are provided.
    #[error("invalid byte {1} at offset {0}")]
    InvalidByte(usize, u8),
}

#[cfg(test)]
pub struct Base64SliceReader<'a> {
    input: &'a [u8],
    input_pos: usize,
    acc: u32,
    bits: u8,
}

#[cfg(test)]
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

#[cfg(test)]
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

/// Bit reader over Base64-URL text.
///
/// Characters are decoded four at a time (three bytes) into a 64-bit buffer.
/// Bits become readable a whole byte at a time, exactly as reading the
/// decoded bytes would allow: the last partial byte of the input is padded
/// with zeros, and an invalid character makes the byte that contains it, and
/// everything after, fail with `InvalidData`.
pub struct Base64BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    /// The low `bits` bits are unread, most significant first.
    acc: u64,
    bits: u32,
    end: Option<End>,
}

#[derive(Clone, Copy)]
enum End {
    Eof,
    InvalidByte(usize, u8),
}

impl<'a> Base64BitReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            acc: 0,
            bits: 0,
            end: None,
        }
    }

    #[inline(always)]
    fn refill(&mut self) {
        while self.bits <= 40 && self.end.is_none() {
            if let Some(&[a, b, c, d]) = self.input.get(self.pos..self.pos + 4) {
                let group = [a, b, c, d].map(|ch| BASE64_DECODE_TABLE[ch as usize]);
                if group.iter().all(|&v| v >= 0) {
                    let value = group.iter().fold(0u64, |acc, &v| (acc << 6) | v as u64);
                    self.acc = (self.acc << 24) | value;
                    self.bits += 24;
                    self.pos += 4;
                    continue;
                }
            }
            self.refill_last_group();
        }
    }

    /// The group of up to four characters that ends the input or holds an
    /// invalid character.
    #[cold]
    fn refill_last_group(&mut self) {
        let mut value = 0u64;
        let mut chars = 0usize;
        let mut end = None;
        while chars < 4 {
            match self.input.get(self.pos + chars) {
                None => {
                    end = Some(End::Eof);
                    break;
                }
                Some(&ch) => match base64_value(ch) {
                    Some(v) => {
                        value = (value << 6) | v as u64;
                        chars += 1;
                    }
                    None => {
                        end = Some(End::InvalidByte(self.pos + chars, ch));
                        break;
                    }
                },
            }
        }
        let decoded_bits = 6 * chars as u32;
        let readable_bits = match end {
            Some(End::Eof) => decoded_bits.div_ceil(8) * 8,
            Some(End::InvalidByte(..)) => decoded_bits / 8 * 8,
            None => decoded_bits,
        };
        let value = if readable_bits >= decoded_bits {
            value << (readable_bits - decoded_bits)
        } else {
            value >> (decoded_bits - readable_bits)
        };
        if readable_bits > 0 {
            self.acc = (self.acc << readable_bits) | value;
            self.bits += readable_bits;
        }
        self.pos += chars;
        self.end = end;
    }

    fn end_error(&self) -> io::Error {
        match self.end {
            Some(End::InvalidByte(offset, byte)) => io::Error::new(
                io::ErrorKind::InvalidData,
                DecodeError::InvalidByte(offset, byte),
            ),
            _ => io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"),
        }
    }

    /// Reads `n <= 32` bits.
    #[inline(always)]
    fn take(&mut self, n: u32) -> io::Result<u64> {
        if self.bits < n {
            self.refill();
            if self.bits < n {
                return Err(self.end_error());
            }
        }
        self.bits -= n;
        Ok((self.acc >> self.bits) & ((1u64 << n) - 1))
    }
}

impl BitRead for Base64BitReader<'_> {
    #[inline(always)]
    fn read_bit(&mut self) -> io::Result<bool> {
        Ok(self.take(1)? == 1)
    }

    #[inline(always)]
    fn read_unsigned_counted<const MAX: u32, U>(&mut self, bits: BitCount<MAX>) -> io::Result<U>
    where
        U: UnsignedInteger,
    {
        let bits = u32::from(bits);
        if bits > U::BITS_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "excessive bits for type read",
            ));
        }
        let value = if bits > 32 {
            (self.take(bits - 32)? << 32) | self.take(32)?
        } else {
            self.take(bits)?
        };
        let mut out = U::ZERO;
        for byte in (0..bits.div_ceil(8)).rev() {
            out = out.shl_default(8) | U::from_u8((value >> (8 * byte)) as u8);
        }
        Ok(out)
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
        while bits > 0 {
            let take = bits.min(32);
            self.take(take)?;
            bits -= take;
        }
        Ok(())
    }

    #[inline(always)]
    fn read_bytes(&mut self, buf: &mut [u8]) -> io::Result<()> {
        for b in buf.iter_mut() {
            *b = self.take(8)? as u8;
        }
        Ok(())
    }

    #[inline(always)]
    fn byte_aligned(&self) -> bool {
        self.bits.is_multiple_of(8)
    }

    #[inline(always)]
    fn byte_align(&mut self) {
        self.bits -= self.bits % 8;
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
    if v >= 0 { Some(v as u8) } else { None }
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

    /// The reader this module used before decoding four characters at a
    /// time; the fast reader must agree with it read for read.
    struct OldBitReader<'a> {
        reader: Base64SliceReader<'a>,
        value: u8,
        bits: u32,
    }

    impl<'a> OldBitReader<'a> {
        fn new(input: &'a [u8]) -> Self {
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

    impl BitRead for OldBitReader<'_> {
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

    #[test]
    fn bit_reader_matches_byte_at_a_time_reader() {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        for case in 0..20_000 {
            let len = next(40) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| match next(60) {
                    0 => b"=. !"[next(4) as usize],
                    _ => ALPHABET[next(64) as usize],
                })
                .collect();
            let mut fast = Base64BitReader::new(&input);
            let mut slow = OldBitReader::new(&input);
            for step in 0.. {
                let ctx = format!(
                    "case {case} {:?} step {step}",
                    String::from_utf8_lossy(&input)
                );
                let (f, s) = match next(8) {
                    0 => (
                        fast.read_bit().map(u64::from),
                        slow.read_bit().map(u64::from),
                    ),
                    1 => {
                        let n = [33, 36, 40, 64][next(4) as usize];
                        (fast.read_var::<u64>(n), slow.read_var::<u64>(n))
                    }
                    2 => {
                        let n = next(30) as u32;
                        (fast.skip(n).map(|()| 0), slow.skip(n).map(|()| 0))
                    }
                    3 => (
                        fast.read_to::<u16>().map(u64::from),
                        slow.read_to::<u16>().map(u64::from),
                    ),
                    4 => {
                        assert_eq!(fast.byte_aligned(), slow.byte_aligned(), "{ctx}");
                        fast.byte_align();
                        slow.byte_align();
                        (Ok(0), Ok(0))
                    }
                    5 => {
                        let n = 1 + next(16) as u32;
                        (
                            fast.read_signed_var::<i16>(n).map(|v| v as u64),
                            slow.read_signed_var::<i16>(n).map(|v| v as u64),
                        )
                    }
                    _ => {
                        let n = next(33) as u32;
                        (
                            fast.read_var::<u32>(n).map(u64::from),
                            slow.read_var::<u32>(n).map(u64::from),
                        )
                    }
                };
                match (f, s) {
                    (Ok(f), Ok(s)) => assert_eq!(f, s, "{ctx}"),
                    (Err(f), Err(s)) => {
                        assert_eq!(f.kind(), s.kind(), "{ctx}");
                        assert_eq!(f.to_string(), s.to_string(), "{ctx}");
                        break;
                    }
                    (f, s) => panic!("{ctx}: fast {f:?}, slow {s:?}"),
                }
            }
        }
    }
}
