//! Browser key storage (ADR-0002, part 6). The long-term key is wrapped with AES-GCM under
//! a non-extractable `CryptoKey`, which JavaScript creates and stores but cannot read. The
//! wrapping happens here, in Rust, so plaintext key bytes never reach JavaScript.
//!
//! This protects a key at rest in IndexedDB. It cannot protect against script running in
//! the same origin, which can ask this code to sign, and that is the browser tier's known
//! limit.
#![forbid(unsafe_code)]

use crypto_provider::{CryptoProvider, Secret, SigningKey, Zeroizing};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, CryptoKey, SubtleCrypto, WorkerGlobalScope};

const IV_LEN: usize = 12;

fn subtle() -> Result<SubtleCrypto, JsValue> {
    let scope = js_sys::global();
    let worker: WorkerGlobalScope = scope
        .dyn_into()
        .map_err(|_| JsValue::from_str("this must run in a Web Worker"))?;
    Ok(worker.crypto()?.subtle())
}

/// Creates a new non-extractable wrapping key.
pub async fn new_wrapping_key() -> Result<CryptoKey, JsValue> {
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"AES-GCM".into())?;
    Reflect::set(&algorithm, &"length".into(), &JsValue::from(256))?;
    let usages = js_sys::Array::of2(&"encrypt".into(), &"decrypt".into());
    let promise = subtle()?.generate_key_with_object(&algorithm, false, &usages)?;
    Ok(JsFuture::from(promise).await?.unchecked_into())
}

fn params(iv: &[u8]) -> AesGcmParams {
    AesGcmParams::new("AES-GCM", &Uint8Array::from(iv))
}

/// Wraps a key's secret. The result is `iv || ciphertext`, which is safe to store.
async fn wrap(
    provider: &dyn CryptoProvider,
    wrapping_key: &CryptoKey,
    key: &dyn SigningKey,
) -> Result<Vec<u8>, JsValue> {
    let secret = key
        .export_secret()
        .ok_or_else(|| JsValue::from_str("this key cannot be wrapped"))?;
    let mut iv = [0u8; IV_LEN];
    provider
        .random(&mut iv)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Web Crypto copies its input before the promise resolves, so this copy of the secret
    // lives only in WebAssembly memory and in the browser's implementation.
    let input = Zeroizing::new(secret.to_vec());
    let promise = subtle()?.encrypt_with_object_and_u8_array(&params(&iv), wrapping_key, &input)?;
    let sealed = Uint8Array::new(&JsFuture::from(promise).await?).to_vec();
    let mut out = iv.to_vec();
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Creates a new signing key and returns it with its wrapped form, for storage.
pub async fn create_identity(
    provider: &dyn CryptoProvider,
    wrapping_key: &CryptoKey,
) -> Result<(Box<dyn SigningKey>, Vec<u8>), JsValue> {
    let key = provider
        .generate_signing_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let wrapped = wrap(provider, wrapping_key, key.as_ref()).await?;
    Ok((key, wrapped))
}

/// Opens a stored signing key.
pub async fn open_identity(
    provider: &dyn CryptoProvider,
    wrapping_key: &CryptoKey,
    wrapped: &[u8],
) -> Result<Box<dyn SigningKey>, JsValue> {
    let secret = unwrap(wrapping_key, wrapped).await?;
    provider
        .import_signing_key(&secret)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Reverses [`wrap`].
async fn unwrap(wrapping_key: &CryptoKey, wrapped: &[u8]) -> Result<Secret, JsValue> {
    if wrapped.len() < IV_LEN {
        return Err(JsValue::from_str("the wrapped key is too short"));
    }
    let (iv, sealed) = wrapped.split_at(IV_LEN);
    let promise = subtle()?.decrypt_with_object_and_u8_array(&params(iv), wrapping_key, sealed)?;
    let plain = Uint8Array::new(&JsFuture::from(promise).await?);
    let mut bytes = Zeroizing::new(vec![0u8; plain.length() as usize]);
    plain.copy_to(&mut bytes);
    // Overwrite the JavaScript-side copy before returning, since nothing else will.
    plain.fill(0, 0, plain.length());
    Ok(bytes)
}
