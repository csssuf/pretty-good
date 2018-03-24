use std::io::prelude::*;

use bzip2::read::{BzDecoder, BzEncoder};
use failure::Error;
use flate2::read::{DeflateDecoder, DeflateEncoder, ZlibDecoder, ZlibEncoder};
use nom::{be_u8, rest};
use nom::{ErrorKind, IResult};
use nom::Err as NomErr;

use types::NomError;

named!(uncompressed_data<Result<CompressedDataPacket, Error>>,
    map!(rest, |x| Ok(CompressedDataPacket::Uncompressed(Vec::from(x))))
);

named!(zip_data<Result<CompressedDataPacket, Error>>,
    map!(rest, |x| CompressedDataPacket::from_zip(x))
);

named!(zlib_data<Result<CompressedDataPacket, Error>>,
    map!(rest, |x| CompressedDataPacket::from_zlib(x))
);

named!(bzip2_data<Result<CompressedDataPacket, Error>>,
    map!(rest, |x| CompressedDataPacket::from_bzip2(x))
);

named!(
    compressed_data<Result<CompressedDataPacket, Error>>,
    switch!(be_u8,
        0 => call!(uncompressed_data) |
        1 => call!(zip_data) |
        2 => call!(zlib_data) |
        3 => call!(bzip2_data)
    )
);

#[derive(Clone, Debug)]
pub enum CompressedDataPacket {
    Uncompressed(Vec<u8>),
    Zip(Vec<u8>),
    Zlib(Vec<u8>),
    Bzip2(Vec<u8>),
}

impl CompressedDataPacket {
    fn from_zip(data: &[u8]) -> Result<CompressedDataPacket, Error> {
        let mut deflater = DeflateDecoder::new(data);
        let mut out = Vec::new();
        deflater.read_to_end(&mut out)?;
        Ok(CompressedDataPacket::Zip(out))
    }

    fn from_zlib(data: &[u8]) -> Result<CompressedDataPacket, Error> {
        let mut deflater = ZlibDecoder::new(data);
        let mut out = Vec::new();
        deflater.read_to_end(&mut out)?;
        Ok(CompressedDataPacket::Zlib(out))
    }

    fn from_bzip2(data: &[u8]) -> Result<CompressedDataPacket, Error> {
        let mut deflater = BzDecoder::new(data);
        let mut out = Vec::new();
        deflater.read_to_end(&mut out)?;
        Ok(CompressedDataPacket::Bzip2(out))
    }

    pub fn from_bytes(data: &[u8]) -> Result<CompressedDataPacket, Error> {
        match compressed_data(data) {
            IResult::Done(_, cdata) => cdata,
            IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
                let e = NomError::from(e);

                bail!(CompressionError::InvalidFormat {
                    reason: format!("{:?}", e),
                })
            }
            IResult::Error(e) => bail!(CompressionError::InvalidFormat {
                reason: format!("{:?}", e),
            }),
            IResult::Incomplete(i) => bail!(CompressionError::InvalidFormat {
                reason: format!("{:?}", i),
            }),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        let mut deflater: Box<Read> = match self {
            &CompressedDataPacket::Uncompressed(ref data) => {
                out.push(0);
                Box::new(&data[..])
            }
            &CompressedDataPacket::Zip(ref data) => {
                out.push(1);
                Box::new(DeflateEncoder::new(&data[..], ::flate2::Compression::best()))
            }
            &CompressedDataPacket::Zlib(ref data) => {
                out.push(2);
                Box::new(ZlibEncoder::new(&data[..], ::flate2::Compression::best()))
            }
            &CompressedDataPacket::Bzip2(ref data) => {
                out.push(3);
                Box::new(BzEncoder::new(&data[..], ::bzip2::Compression::Best))
            }
        };

        deflater.read_to_end(&mut out)?;

        Ok(out)
    }
}

#[derive(Debug, Fail)]
pub enum CompressionError {
    #[fail(display = "Invalid compressed data: {}", reason)]
    InvalidFormat { reason: String },
}
