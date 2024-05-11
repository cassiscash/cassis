use secp256k1::{schnorr::Signature, Message};
use std::fmt;

#[derive(Debug)]
pub struct SecretKey(pub(crate) secp256k1::Keypair);

#[derive(Debug, Clone)]
pub struct KeyParseError;

impl fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid secret key hex, must be 64 characters")
    }
}

impl SecretKey {
    pub fn from_hex(s: &String) -> Result<Self, KeyParseError> {
        let mut sk_slice = [0u8; 32];
        hex::decode_to_slice(s, &mut sk_slice).map_err(|_| KeyParseError {})?;
        let sk = secp256k1::SecretKey::from_slice(&sk_slice).map_err(|_| KeyParseError {})?;
        let keypair = secp256k1::Keypair::from_secret_key(secp256k1::global::SECP256K1, &sk);
        Ok(SecretKey(keypair))
    }

    pub fn public(&self) -> PublicKey {
        let (pk, _) = self.0.x_only_public_key();
        PublicKey(pk)
    }

    pub fn sign(&self, digest: [u8; 32]) -> [u8; 64] {
        self.0
            .sign_schnorr(Message::from_digest(digest))
            .serialize()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PublicKey(pub(crate) secp256k1::XOnlyPublicKey);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.serialize()))
    }
}

impl PublicKey {
    pub fn from_hex(s: &String) -> Result<Self, KeyParseError> {
        let mut pk_slice = [0u8; 32];
        hex::decode_to_slice(s, &mut pk_slice).map_err(|_| KeyParseError {})?;
        let keypair = secp256k1::XOnlyPublicKey::from_slice(pk_slice.as_slice())
            .map_err(|_| KeyParseError {})?;
        Ok(PublicKey(keypair))
    }

    pub fn serialize(&self) -> [u8; 32] {
        self.0.serialize()
    }

    pub fn verify(&self, sig: [u8; 64], digest: [u8; 32]) -> Result<(), secp256k1::Error> {
        let message = Message::from_digest(digest);
        if Signature::from(&sig)
            .and_then(|sig| self.0.verify(&sig, &message))
            .is_err()
        {
            return Err(anyhow!("invalid signature"));
        }

        sig.verify(&msg, &self.0)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 32] = hex::serde::deserialize(deserializer)?;
        match secp256k1::XOnlyPublicKey::from_slice(&bytes) {
            Ok(pk) => Ok(PublicKey(pk)),
            Err(err) => Err(<D::Error as serde::de::Error>::custom(format!(
                "not a valid pubkey: {}",
                err
            ))),
        }
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex::serde::serialize(self.0.serialize(), serializer)
    }
}
