#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    Rsa = 1,
    RsaEncryptOnly = 2,
    RsaSignOnly = 3,
    ElgamalEncryptOnly = 16,
    Dsa = 17,
    EllipticCurve = 18,
    Ecdsa = 19,
    Elgamal = 20,
    DiffieHellman = 21,
    Unknown = 255,
}

impl From<u8> for PublicKeyAlgorithm {
    fn from(val: u8) -> PublicKeyAlgorithm {
        match val {
            1 => PublicKeyAlgorithm::Rsa,
            2 => PublicKeyAlgorithm::RsaEncryptOnly,
            3 => PublicKeyAlgorithm::RsaSignOnly,
            16 => PublicKeyAlgorithm::ElgamalEncryptOnly,
            17 => PublicKeyAlgorithm::Dsa,
            18 => PublicKeyAlgorithm::EllipticCurve,
            19 => PublicKeyAlgorithm::Ecdsa,
            20 => PublicKeyAlgorithm::Elgamal,
            21 => PublicKeyAlgorithm::DiffieHellman,
            _ => PublicKeyAlgorithm::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Md5 = 1,
    Sha1 = 2,
    Ripemd160 = 3,
    Sha256 = 8,
    Sha384 = 9,
    Sha512 = 10,
    Sha224 = 11,
    Unknown = 255,
}

impl From<u8> for HashAlgorithm {
    fn from(val: u8) -> HashAlgorithm {
        match val {
            1 => HashAlgorithm::Md5,
            2 => HashAlgorithm::Sha1,
            3 => HashAlgorithm::Ripemd160,
            8 => HashAlgorithm::Sha256,
            9 => HashAlgorithm::Sha384,
            10 => HashAlgorithm::Sha512,
            11 => HashAlgorithm::Sha224,
            _ => HashAlgorithm::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum NomError {
    Unimplemented = 1,
    UseOfReservedValue = 2,
    IntegerReadError = 3,
    Unknown,
}

impl From<u32> for NomError {
    fn from(val: u32) -> NomError {
        match val {
            1 => NomError::Unimplemented,
            2 => NomError::UseOfReservedValue,
            3 => NomError::IntegerReadError,
            _ => NomError::Unknown,
        }
    }
}
