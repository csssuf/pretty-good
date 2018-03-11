use std::str;
use std::time::Duration;

use byteorder::{BigEndian, WriteBytesExt};
use failure::Error;
use nom::{rest, be_u32, be_u8};
use nom::{ErrorKind, IResult};
use nom::Err as NomErr;

use types::NomError;

named!(binary_tag, tag!("b"));
named!(text_tag, alt!(tag!("t") | tag!("u")));

named!(
    read_timestamp<Duration>,
    map!(be_u32, |t| Duration::from_secs(u64::from(t)))
);

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    literal_data<Result<LiteralPacket, Error>>,
    do_parse!(
        tag: map_res!(alt!(binary_tag | text_tag), str::from_utf8) >>
        filename: map_res!(length_data!(be_u8), str::from_utf8) >>
        timestamp: read_timestamp >>
        contents: rest >>
        (LiteralData::new(tag, contents).map(|data| {
            LiteralPacket {
                filename: String::from(filename),
                timestamp,
                contents: data,
            }
        }))
    )
);

/// A Literal data packet as specified in [RFC4880 &sect;5.9].
///
/// [RFC4880 &sect;5.9]: https://tools.ietf.org/html/rfc4880#section-5.9
#[derive(Clone, Debug)]
pub struct LiteralPacket {
    pub filename: String,
    pub timestamp: Duration,
    pub contents: LiteralData,
}

impl LiteralPacket {
    pub fn from_bytes(bytes: &[u8]) -> Result<LiteralPacket, Error> {
        match literal_data(bytes) {
            IResult::Done(_, sig) => sig,
            IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
                let e = NomError::from(e);

                bail!(LiteralError::InvalidFormat {
                    reason: format!("{:?}", e),
                })
            }
            IResult::Error(e) => bail!(LiteralError::InvalidFormat {
                reason: format!("{}", e),
            }),
            IResult::Incomplete(i) => bail!(LiteralError::InvalidFormat {
                reason: format!("{:?}", i),
            }),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        match self.contents {
            LiteralData::Binary(_) => out.push(0x62), // 0x62 == 'b'
            LiteralData::Text(_) => out.push(0x75),   // 0x75 == 'u'
        };

        let filename = self.filename.as_bytes();
        if filename.len() > 255 {
            bail!(LiteralError::FilenameTooLong);
        }
        out.push(filename.len() as u8);
        out.extend(filename);

        out.write_u32::<BigEndian>(self.timestamp.as_secs() as u32)?;

        match self.contents {
            LiteralData::Binary(ref data) => out.extend(data),
            LiteralData::Text(ref data) => out.extend(data.as_bytes()),
        };

        Ok(out)
    }
}

/// The contents of a [`LiteralPacket`].
///
/// [`LiteralPacket`]: struct.LiteralPacket.html
#[derive(Clone, Debug)]
pub enum LiteralData {
    Binary(Vec<u8>),
    Text(String),
}

impl LiteralData {
    fn new(tag: &str, contents: &[u8]) -> Result<LiteralData, Error> {
        match tag {
            "b" => Ok(LiteralData::Binary(Vec::from(contents))),
            "t" | "u" => Ok(LiteralData::Text(String::from(str::from_utf8(contents)?))),
            _ => bail!(LiteralError::InvalidTag {
                tag: String::from(tag),
            }),
        }
    }
}

/// Error type for [`LiteralPacket`]-level errors.
///
/// [`LiteralPacket`]: struct.LiteralPacket.html
#[derive(Debug, Fail)]
pub enum LiteralError {
    #[fail(display = "Invalid literal format: {}", reason)]
    InvalidFormat { reason: String },
    #[fail(display = "Literal filename too long")]
    FilenameTooLong,
    #[fail(display = "Invalid literal type tag: {}", tag)]
    InvalidTag { tag: String },
}
