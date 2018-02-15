use failure::Error;

#[derive(Clone, Debug)]
pub struct SignaturePacket {
    contents: Vec<u8>
}

impl SignaturePacket {
    pub fn from_bytes(bytes: &[u8]) -> Result<SignaturePacket, Error> {
        Ok(SignaturePacket{
            contents: Vec::from(bytes)
        })
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}
