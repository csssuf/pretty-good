use std::time::Duration;

use byteorder::{BigEndian, ReadBytesExt};
use nom::{ErrorKind, IResult, be_u16};
use nom::Err as NomErr;
use num::BigUint;

use types::*;

pub(crate) fn parse_time_subpacket<T>(mut inp: &[u8]) -> Result<Duration, NomErr<T>> {
    inp.read_u32::<BigEndian>()
        .map(|seconds| Duration::from_secs(u64::from(seconds)))
        .map_err(|_| NomErr::Code(ErrorKind::Custom(NomError::IntegerReadError as u32)))
}

named!(
    pub pgp_time<Duration>,
    map_res!(take!(4), parse_time_subpacket::<&[u8]>)
);

pub(crate) fn pgp_mpi(inp: &[u8]) -> IResult<&[u8], BigUint> {
    let (remaining, length_bits) = match be_u16(inp) {
        IResult::Done(remaining, length_bits) => (remaining, length_bits),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    let length_bytes = (length_bits + 7) / 8;

    let (remaining, mpi_slice) = match take!(remaining, length_bytes) {
        IResult::Done(remaining, mpi_slice) => (remaining, mpi_slice),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    IResult::Done(remaining, BigUint::from_bytes_be(mpi_slice))
}
