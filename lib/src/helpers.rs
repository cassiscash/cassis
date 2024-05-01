use secp256k1::XOnlyPublicKey;

pub fn serialize_xonlypubkey<S>(pk: &XOnlyPublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    hex::serde::serialize(pk.serialize(), serializer)
}

pub fn deserialize_xonlypubkey<'de, D>(deserializer: D) -> Result<XOnlyPublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: [u8; 32] = hex::serde::deserialize(deserializer)?;
    match XOnlyPublicKey::from_slice(&bytes) {
        Ok(pk) => Ok(pk),
        Err(err) => Err(<D::Error as serde::de::Error>::custom(format!(
            "not a valid pubkey: {}",
            err
        ))),
    }
}
