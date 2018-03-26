use failure::Error;
use nom::be_u8;
use nom::{ErrorKind, IResult};
use nom::Err as NomErr;

use types::*;

pub(crate) fn s2k_iv(inp: &[u8]) -> IResult<&[u8], [u8; 8]> {
    let mut out = [0u8; 8];

    let (remaining, slice) = match take!(inp, 8) {
        IResult::Done(remaining, slice) => (remaining, slice),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    out.copy_from_slice(&slice[..8]);

    IResult::Done(remaining, out)
}

fn s2k_decode_count(c: u8) -> u32 {
    let c = c as u32;
    (16 + (c & 15)) << ((c >> 4) + 6)
}

named!(simple_s2k<StringToKey>,
    do_parse!(
        tag!(&[0u8]) >>
        hash_algo: map!(be_u8, HashAlgorithm::from) >>
        (StringToKey::Simple(hash_algo))
    )
);

named!(salted_s2k<StringToKey>,
    do_parse!(
        tag!(&[1u8]) >>
        hash_algo: map!(be_u8, HashAlgorithm::from) >>
        iv: s2k_iv >>
        (StringToKey::Salted(hash_algo, iv))
    )
);

named!(iterated_salted_s2k<StringToKey>,
    do_parse!(
        tag!(&[3u8]) >>
        hash_algo: map!(be_u8, HashAlgorithm::from) >>
        iv: s2k_iv >>
        count: map!(be_u8, s2k_decode_count) >>
        (StringToKey::IteratedSalted(hash_algo, iv, count))
    )
);

named!(pub s2k<StringToKey>, alt!(simple_s2k | salted_s2k | iterated_salted_s2k));

#[derive(Clone, Copy, Debug)]
pub enum StringToKey {
    Simple(HashAlgorithm),
    Salted(HashAlgorithm, [u8; 8]),
    IteratedSalted(HashAlgorithm, [u8; 8], u32),
}

impl StringToKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<StringToKey, Error> {
        let (_, string_to_key) = match s2k(bytes) {
            IResult::Done(remaining, string_to_key) => (remaining, string_to_key),
            IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
                let e = NomError::from(e);

                bail!(S2kError::InvalidFormat {
                    reason: format!("{:?}", e),
                })
            }
            IResult::Error(e) => bail!(S2kError::InvalidFormat {
                reason: format!("{}", e),
            }),
            IResult::Incomplete(i) => bail!(S2kError::InvalidFormat {
                reason: format!("{:?}", i),
            }),
        };

        Ok(string_to_key)
    }
}

#[derive(Debug, Fail)]
pub enum S2kError {
    #[fail(display = "Invalid string to key specifier: {}", reason)]
    InvalidFormat { reason: String },
}
