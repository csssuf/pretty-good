use std::time::Duration;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use digest::Digest;
use failure::Error;
use md5::Md5;
use nom::{be_u16, be_u8, ErrorKind, IResult};
use nom::Err as NomErr;
use num::BigUint;
use sha1::Sha1;

use s2k::{StringToKey, s2k};
use types::*;
use util::{pgp_mpi, pgp_time};

named!(
    rsa_pubkey<RsaPublicKey>,
    do_parse!(
        n: pgp_mpi >>
        e: pgp_mpi >>
        (RsaPublicKey { n, e })
    )
);

named!(
    rsa_privkey<RsaPrivateKey>,
    do_parse!(
        d: pgp_mpi >>
        p: pgp_mpi >>
        q: pgp_mpi >>
        u: pgp_mpi >>
        (RsaPrivateKey { d, p, q, u })
    )
);

named!(
    dsa_pubkey<DsaPublicKey>,
    do_parse!(
        p: pgp_mpi >>
        q: pgp_mpi >>
        g: pgp_mpi >>
        y: pgp_mpi >>
        (DsaPublicKey { p, q, g, y })
    )
);

named!(dsa_privkey<DsaPrivateKey>, map!(pgp_mpi, DsaPrivateKey));

named!(
    elgamal_pubkey<ElgamalPublicKey>,
    do_parse!(
        p: pgp_mpi >>
        g: pgp_mpi >>
        y: pgp_mpi >>
        (ElgamalPublicKey { p, g, y })
    )
);

named!(elgamal_privkey<ElgamalPrivateKey>, map!(pgp_mpi, ElgamalPrivateKey));

named!(
    v3_pubkey<Key>,
    do_parse!(
        alt!(tag!(&[2_u8]) | tag!(&[3_u8])) >>
        created: pgp_time >>
        expires_days: be_u16 >>
        pubkey_algo: be_u8 >>
        rsa_n: pgp_mpi >>
        rsa_e: pgp_mpi >>
        (Key {
            version: KeyVersion::V3,
            creation_time: created,
            expiration_time: Some(Duration::from_secs(expires_days as u64 * 24 * 60 * 60)),
            pubkey_algorithm: PublicKeyAlgorithm::from(pubkey_algo),
            key_material: KeyMaterial::Rsa(RsaPublicKey { n: rsa_n, e: rsa_e }, None),
            encryption_method: None,
            privkey_checksum: None,
        })
    )
);

named!(
    v4_pubkey<Key>,
    do_parse!(
        tag!(&[4_u8]) >>
        created: pgp_time >>
        pubkey_algorithm: peek!(be_u8) >>
        pubkey_material: switch!(map!(be_u8, PublicKeyAlgorithm::from),
            PublicKeyAlgorithm::Rsa => map!(call!(rsa_pubkey), |k| KeyMaterial::Rsa(k, None)) |
            PublicKeyAlgorithm::RsaSignOnly => map!(
                call!(rsa_pubkey),
                |k| KeyMaterial::Rsa(k, None)
            ) |
            PublicKeyAlgorithm::RsaEncryptOnly => map!(
                call!(rsa_pubkey),
                |k| KeyMaterial::Rsa(k, None)
            ) |
            PublicKeyAlgorithm::Dsa => map!(call!(dsa_pubkey), |k| KeyMaterial::Dsa(k, None)) |
            PublicKeyAlgorithm::Elgamal => map!(
                call!(elgamal_pubkey),
                |k| KeyMaterial::Elgamal(k, None)
            ) |
            PublicKeyAlgorithm::ElgamalEncryptOnly => map!(
                call!(elgamal_pubkey),
                |k| KeyMaterial::Elgamal(k, None)
            )) >>
        (Key {
            version: KeyVersion::V4,
            creation_time: created,
            expiration_time: None,
            pubkey_algorithm: PublicKeyAlgorithm::from(pubkey_algorithm),
            key_material: pubkey_material,
            encryption_method: None,
            privkey_checksum: None,
        })
    )
);

named!(pubkey<Key>, alt!(v3_pubkey | v4_pubkey));

named!(privkey_prefix_unencrypted<KeyEncryptionMethod>,
    do_parse!(
        tag!(&[0u8]) >>
        (KeyEncryptionMethod::Unencrypted)
    )
);

named!(privkey_prefix_symmetric<KeyEncryptionMethod>,
    do_parse!(
        enc_type: map!(be_u8, SymmetricKeyAlgorithm::from) >>
        iv: take!(enc_type.block_bytes()) >>
        (KeyEncryptionMethod::SymmetricKey(enc_type, Vec::from(iv)))
    )
);

named!(privkey_prefix_s2k<KeyEncryptionMethod>,
    do_parse!(
        tag!(&[255u8]) >>
        enc_type: map!(be_u8, SymmetricKeyAlgorithm::from) >>
        s2k_specifier: s2k >>
        iv: take!(enc_type.block_bytes()) >>
        (KeyEncryptionMethod::StringToKey(enc_type, Vec::from(iv), s2k_specifier))
    )
);

named!(privkey_prefix_s2k_sha1<KeyEncryptionMethod>,
    do_parse!(
        tag!(&[254u8]) >>
        enc_type: map!(be_u8, SymmetricKeyAlgorithm::from) >>
        s2k_specifier: s2k >>
        iv: take!(enc_type.block_bytes()) >>
        (KeyEncryptionMethod::StringToKeySha1(enc_type, Vec::from(iv), s2k_specifier))
    )
);

named!(privkey_prefix<KeyEncryptionMethod>,
    alt!(privkey_prefix_unencrypted |
         privkey_prefix_s2k |
         privkey_prefix_s2k_sha1 |
         privkey_prefix_symmetric
    )
);

fn parse_key(inp: &[u8]) -> IResult<&[u8], Key> {
    let (remaining, mut key) = match pubkey(inp) {
        IResult::Done(remaining, key) => (remaining, key),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(i) => return IResult::Incomplete(i),
    };

    let (remaining, privkey_prefix) = match privkey_prefix(remaining) {
        IResult::Done(remaining, prefix) => (remaining, prefix),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(_) => return IResult::Done(remaining, key),
    };

    let (remaining, privkey_material) = match key.key_material {
        KeyMaterial::Rsa(ref pub_material, _) => match rsa_privkey(remaining) {
            IResult::Done(remaining, privkey) => (remaining, KeyMaterial::Rsa(pub_material.clone(), Some(privkey))),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        },
        KeyMaterial::Dsa(ref pub_material, _) => match dsa_privkey(remaining) {
            IResult::Done(remaining, privkey) => (remaining, KeyMaterial::Dsa(pub_material.clone(), Some(privkey))),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        },
        KeyMaterial::Elgamal(ref pub_material, _) => match elgamal_privkey(remaining) {
            IResult::Done(remaining, privkey) => (remaining, KeyMaterial::Elgamal(pub_material.clone(), Some(privkey))),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        }
    };

    let (remaining, checksum) = match privkey_prefix {
        KeyEncryptionMethod::Unencrypted
        | KeyEncryptionMethod::SymmetricKey(_, _)
        | KeyEncryptionMethod::StringToKey(_, _, _) => match take!(remaining, 2) {
            IResult::Done(remaining, checksum) => (remaining, checksum),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        }
        KeyEncryptionMethod::StringToKeySha1(_, _, _) => match take!(remaining, 20) {
            IResult::Done(remaining, checksum) => (remaining, checksum),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i),
        }
    };

    key.key_material = privkey_material;
    key.encryption_method = Some(privkey_prefix);
    key.privkey_checksum = Some(Vec::from(checksum));

    IResult::Done(remaining, key)
}

#[derive(Clone, Debug)]
pub struct Key {
    version: KeyVersion,
    pub creation_time: Duration,
    expiration_time: Option<Duration>,
    pub pubkey_algorithm: PublicKeyAlgorithm,
    pub key_material: KeyMaterial,
    pub encryption_method: Option<KeyEncryptionMethod>,
    pub privkey_checksum: Option<Vec<u8>>,
}

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> Result<Key, Error> {
        let (_, key) = match parse_key(bytes) {
            IResult::Done(remaining, key) => (remaining, key),
            IResult::Error(NomErr::Code(ErrorKind::Custom(e))) => {
                let e = NomError::from(e);

                bail!(KeyError::InvalidFormat {
                    reason: format!("{:?}", e),
                })
            }
            IResult::Error(e) => bail!(KeyError::InvalidFormat {
                reason: format!("{}", e),
            }),
            IResult::Incomplete(i) => bail!(KeyError::InvalidFormat {
                reason: format!("{:?}", i),
            }),
        };

        Ok(key)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        out.push(4u8);
        out.write_u32::<BigEndian>(self.creation_time.as_secs() as u32)?;
        out.push(self.pubkey_algorithm as u8);
        out.extend(&self.key_material.public_to_bytes()?);

        let private_bytes = self.key_material.private_to_bytes()?;
        if !private_bytes.is_empty() {
            match self.encryption_method {
                None => bail!(KeyError::InvalidEncryption),
                Some(KeyEncryptionMethod::Unencrypted) => {
                    out.push(0u8);
                    match self.privkey_checksum {
                        None => bail!(KeyError::BadChecksum),
                        Some(ref checksum) => {
                            out.extend(&private_bytes);
                            out.extend(checksum);
                        }
                    }
                }
                Some(ref e) => bail!(KeyError::UnimplementedEncryption {
                    method: format!("{:?}", e),
                })
            }
        }

        Ok(out)
    }

    pub fn expiration_time(&self) -> Option<Duration> {
        self.expiration_time
    }

    pub fn fingerprint(&self) -> Result<Vec<u8>, Error> {
        match self.version {
            KeyVersion::V3 => {
                let hash_payload = self.key_material.public_to_bytes()?;
                Ok(Vec::from(Md5::digest(&hash_payload).as_ref()))
            }
            KeyVersion::V4 => {
                let mut hash_payload = Vec::new();
                hash_payload.push(0x99);

                let mut key_data = Vec::new();
                key_data.push(0x4);
                key_data.write_u32::<BigEndian>(self.creation_time.as_secs() as u32)?;
                key_data.push(self.pubkey_algorithm as u8);
                key_data.extend(self.key_material.public_to_bytes()?);

                hash_payload.write_u16::<BigEndian>(key_data.len() as u16)?;
                hash_payload.extend(&key_data);

                Ok(Vec::from(Sha1::digest(&hash_payload).as_ref()))
            }
        }
    }

    pub fn id(&self) -> Result<u64, Error> {
        let bytes = match self.version {
            KeyVersion::V3 => match self.key_material {
                KeyMaterial::Rsa(ref pubkey, _) => {
                    let n = pubkey.n.to_bytes_be();
                    Ok(Vec::from(&n[n.len() - 8..]))
                }
                KeyMaterial::Dsa(_, _) => bail!("v3 DSA keys are unsupported"),
                KeyMaterial::Elgamal(_, _) => bail!("v3 Elgamal keys are unsupported"),
            },
            KeyVersion::V4 => self.fingerprint().map(|mut f| {
                let len = f.len();
                f.split_off(len - 8)
            }),
        }?;

        Ok(BigEndian::read_u64(&bytes))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum KeyVersion {
    V3,
    V4,
}

#[derive(Clone, Debug)]
pub enum KeyMaterial {
    Rsa(RsaPublicKey, Option<RsaPrivateKey>),
    Dsa(DsaPublicKey, Option<DsaPrivateKey>),
    Elgamal(ElgamalPublicKey, Option<ElgamalPrivateKey>),
}

impl KeyMaterial {
    pub fn public_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        match self {
            &KeyMaterial::Rsa(ref public, _) => {
                out.write_u16::<BigEndian>(public.n.bits() as u16)?;
                out.extend(&public.n.to_bytes_be());
                out.write_u16::<BigEndian>(public.e.bits() as u16)?;
                out.extend(&public.e.to_bytes_be());
            }
            &KeyMaterial::Dsa(ref public, _) => {
                out.write_u16::<BigEndian>(public.p.bits() as u16)?;
                out.extend(&public.p.to_bytes_be());
                out.write_u16::<BigEndian>(public.q.bits() as u16)?;
                out.extend(&public.q.to_bytes_be());
                out.write_u16::<BigEndian>(public.g.bits() as u16)?;
                out.extend(&public.g.to_bytes_be());
                out.write_u16::<BigEndian>(public.y.bits() as u16)?;
                out.extend(&public.y.to_bytes_be());
            }
            &KeyMaterial::Elgamal(ref public, _) => {
                out.write_u16::<BigEndian>(public.p.bits() as u16)?;
                out.extend(&public.p.to_bytes_be());
                out.write_u16::<BigEndian>(public.g.bits() as u16)?;
                out.extend(&public.g.to_bytes_be());
                out.write_u16::<BigEndian>(public.y.bits() as u16)?;
                out.extend(&public.y.to_bytes_be());
            }
        }

        Ok(out)
    }

    pub fn private_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        match self {
            &KeyMaterial::Rsa(_, Some(ref private)) => {
                out.write_u16::<BigEndian>(private.d.bits() as u16)?;
                out.extend(&private.d.to_bytes_be());
                out.write_u16::<BigEndian>(private.p.bits() as u16)?;
                out.extend(&private.p.to_bytes_be());
                out.write_u16::<BigEndian>(private.q.bits() as u16)?;
                out.extend(&private.q.to_bytes_be());
                out.write_u16::<BigEndian>(private.u.bits() as u16)?;
                out.extend(&private.u.to_bytes_be());
            }
            &KeyMaterial::Dsa(_, Some(DsaPrivateKey(ref private))) => {
                out.write_u16::<BigEndian>(private.bits() as u16)?;
                out.extend(&private.to_bytes_be());
            }
            &KeyMaterial::Elgamal(_, Some(ElgamalPrivateKey(ref private))) => {
                out.write_u16::<BigEndian>(private.bits() as u16)?;
                out.extend(&private.to_bytes_be());
            }
            &KeyMaterial::Rsa(_, None)
            | &KeyMaterial::Dsa(_, None)
            | &KeyMaterial::Elgamal(_, None) => {}
        }

        Ok(out)
    }
}

#[derive(Clone, Debug)]
pub enum KeyEncryptionMethod {
    Unencrypted,
    SymmetricKey(SymmetricKeyAlgorithm, Vec<u8>),
    StringToKey(SymmetricKeyAlgorithm, Vec<u8>, StringToKey),
    StringToKeySha1(SymmetricKeyAlgorithm, Vec<u8>, StringToKey)
}

#[derive(Clone, Debug)]
pub struct RsaPublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Clone, Debug)]
pub struct RsaPrivateKey {
    pub d: BigUint,
    pub p: BigUint,
    pub q: BigUint,
    pub u: BigUint,
}

#[derive(Clone, Debug)]
pub struct DsaPublicKey {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub y: BigUint,
}

#[derive(Clone, Debug)]
pub struct DsaPrivateKey(pub BigUint);

#[derive(Clone, Debug)]
pub struct ElgamalPublicKey {
    pub p: BigUint,
    pub g: BigUint,
    pub y: BigUint,
}

#[derive(Clone, Debug)]
pub struct ElgamalPrivateKey(pub BigUint);

#[derive(Debug, Fail)]
pub enum KeyError {
    #[fail(display = "Invalid key format: {}", reason)]
    InvalidFormat { reason: String },
    #[fail(display = "Invalid/no encryption set")]
    InvalidEncryption,
    #[fail(display = "Bad checksum")]
    BadChecksum,
    #[fail(display = "Unimplemented key encryption method: {}", method)]
    UnimplementedEncryption { method: String },
    #[fail(display = "Malformed MPI payload")]
    MalformedMpi,
}
