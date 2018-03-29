use std::str;

use failure::Error;
use nom::{rest, IResult};

pub(crate) fn parse_userid(inp: &[u8]) -> Result<String, Error> {
    match rest(inp) {
        IResult::Done(_, s) => Ok(String::from(str::from_utf8(s)?)),
        IResult::Error(e) => bail!(UserIdError::NomError {
            reason: format!("{}", e),
        }),
        IResult::Incomplete(i) => bail!(UserIdError::NomError {
            reason: format!("{:?}", i),
        }),
    }
}

#[derive(Debug, Fail)]
pub enum UserIdError {
    #[fail(display = "Error parsing user ID: {}", reason)]
    NomError { reason: String },
}
