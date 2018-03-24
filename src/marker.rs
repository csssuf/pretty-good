use failure::Error;
use nom::{ErrorKind, IResult};
use nom::Err as NomErr;

use types::*;

named!(marker, tag!(&[0x50u8, 0x47u8, 0x50u8]));

pub(crate) static MARKER_PACKET: &[u8] = &[0x50u8, 0x47u8, 0x50u8];

pub(crate) fn verify_marker(bytes: &[u8]) -> Result<(), Error> {
    match marker(bytes) {
        IResult::Done(_, _) => Ok(()),
        IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
            let e = NomError::from(e);

            bail!(MarkerError::Invalid {
                reason: format!("{:?}", e),
            })
        }
        IResult::Error(e) => bail!(MarkerError::Invalid {
            reason: format!("{:?}", e),
        }),
        IResult::Incomplete(i) => bail!(MarkerError::Invalid {
            reason: format!("{:?}", i),
        }),
    }
}

#[derive(Debug, Fail)]
pub enum MarkerError {
    #[fail(display = "Invalid marker: {}", reason)]
    Invalid { reason: String },
}
