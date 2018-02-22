use asn1::ObjectIdentifier;
use failure::Error;

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

impl From<PublicKeyAlgorithm> for u8 {
    fn from(val: PublicKeyAlgorithm) -> u8 {
        match val {
            PublicKeyAlgorithm::Rsa => 1,
            PublicKeyAlgorithm::RsaEncryptOnly => 2,
            PublicKeyAlgorithm::RsaSignOnly => 3,
            PublicKeyAlgorithm::ElgamalEncryptOnly => 16,
            PublicKeyAlgorithm::Dsa => 17,
            PublicKeyAlgorithm::EllipticCurve => 18,
            PublicKeyAlgorithm::Ecdsa => 19,
            PublicKeyAlgorithm::Elgamal => 20,
            PublicKeyAlgorithm::DiffieHellman => 21,
            PublicKeyAlgorithm::Unknown => 0xFF,
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

impl From<HashAlgorithm> for u8 {
    fn from(val: HashAlgorithm) -> u8 {
        match val {
            HashAlgorithm::Md5 => 1,
            HashAlgorithm::Sha1 => 2,
            HashAlgorithm::Ripemd160 => 3,
            HashAlgorithm::Sha256 => 8,
            HashAlgorithm::Sha384 => 9,
            HashAlgorithm::Sha512 => 10,
            HashAlgorithm::Sha224 => 11,
            HashAlgorithm::Unknown => 0xFF,
        }
    }
}

impl HashAlgorithm {
    pub fn asn1_oid(&self) -> Result<ObjectIdentifier, Error> {
        let oid_vec = match *self {
            HashAlgorithm::Md5 => vec![1, 2, 840, 113549, 2, 5],
            HashAlgorithm::Sha1 => vec![1, 3, 14, 3, 2, 26],
            HashAlgorithm::Ripemd160 => vec![1, 3, 36, 3, 2, 1],
            HashAlgorithm::Sha256 => vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
            HashAlgorithm::Sha384 => vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
            HashAlgorithm::Sha512 => vec![2, 16, 840, 1, 101, 3, 4, 2, 3],
            HashAlgorithm::Sha224 => vec![2, 16, 840, 1, 101, 3, 4, 2, 4],
            HashAlgorithm::Unknown => bail!(AlgorithmError::HashAlgorithmError),
        };

        ObjectIdentifier::new(oid_vec)
            .ok_or(AlgorithmError::HashAlgorithmError.into())
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

#[derive(Clone, Debug, Fail)]
pub enum AlgorithmError {
    #[fail(display = "unknown public key algorithm")]
    PublicKeyAlgorithmError,
    #[fail(display = "unknown hash algorithm")]
    HashAlgorithmError,
}
