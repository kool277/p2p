//! Published vectors for the constructions the protocol composes. These check the
//! generic HMAC, HKDF and encrypt-then-MAC code in `crypto-provider`.
//!
//! **They are not the official O'z DSt control examples**, which the Phase 1 gate
//! requires. Those wait for the certified library.

use crypto_provider::{AeadKey, CryptoError, CryptoProvider, from_hex, secret, to_hex};
use provider_testonly::TestOnlyProvider;

fn hex(s: &str) -> Vec<u8> {
    from_hex(s).expect("valid hex")
}

fn p() -> TestOnlyProvider {
    TestOnlyProvider::new()
}

#[test]
fn self_test_passes() {
    p().self_test().unwrap();
}

#[test]
fn sha256_fips180_vectors() {
    assert_eq!(
        to_hex(&p().hash(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        to_hex(&p().hash(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

// RFC 4231 test cases 1, 2, 3, 6 and 7, for HMAC-SHA-256. Cases 6 and 7 use a key
// longer than the hash block, which exercises the key-hashing branch.
#[test]
fn hmac_rfc4231() {
    let cases: [(Vec<u8>, Vec<u8>, &str); 5] = [
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            vec![0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            vec![0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (key, data, expected) in cases {
        assert_eq!(to_hex(&p().mac(&key, &data)), expected);
    }
}

// RFC 5869 test cases 1, 2 and 3, for HKDF-SHA-256.
#[test]
fn hkdf_rfc5869() {
    let case1_salt = hex("000102030405060708090a0b0c");
    let case1_info = hex("f0f1f2f3f4f5f6f7f8f9");
    let prk = p().hkdf_extract(&case1_salt, &[0x0b; 22]);
    assert_eq!(
        to_hex(&prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    assert_eq!(
        to_hex(&p().hkdf_expand(&prk, &case1_info, 42).unwrap()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    let prk = p().hkdf_extract(&salt, &ikm);
    assert_eq!(
        to_hex(&prk),
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    );
    assert_eq!(
        to_hex(&p().hkdf_expand(&prk, &info, 82).unwrap()),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );

    let prk = p().hkdf_extract(&[], &[0x0b; 22]);
    assert_eq!(
        to_hex(&prk),
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    );
    assert_eq!(
        to_hex(&p().hkdf_expand(&prk, &[], 42).unwrap()),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn hkdf_refuses_too_much_output() {
    assert_eq!(
        p().hkdf_expand(&[0u8; 32], &[], 255 * 32 + 1).unwrap_err(),
        CryptoError::InvalidInput
    );
    assert!(p().hkdf_expand(&[0u8; 32], &[], 255 * 32).is_ok());
}

#[test]
fn etm_tag_covers_aad_length_and_ciphertext() {
    let key = AeadKey {
        enc: secret(&[1u8; 32]),
        mac: secret(&[2u8; 32]),
    };
    let nonce = [0u8; 12];
    let p = p();
    let sealed = p.aead_seal(&key, &nonce, b"header", b"payload").unwrap();
    assert_eq!(sealed.len(), 7 + 32);

    // Moving bytes between the associated data and the ciphertext changes the tag,
    // because the length of the associated data is authenticated.
    let mut moved_aad = b"header".to_vec();
    moved_aad.push(sealed[0]);
    assert!(p.aead_open(&key, &nonce, &moved_aad, &sealed[1..]).is_err());

    assert!(p.aead_open(&key, &nonce, b"headeR", &sealed).is_err());
    assert!(p.aead_open(&key, &[1u8; 12], b"header", &sealed).is_err());
    let other = AeadKey {
        enc: secret(&[1u8; 32]),
        mac: secret(&[3u8; 32]),
    };
    assert!(p.aead_open(&other, &nonce, b"header", &sealed).is_err());
    assert!(p.aead_open(&key, &nonce, b"header", &sealed[..10]).is_err());
    assert_eq!(
        p.aead_open(&key, &nonce, b"header", &sealed)
            .unwrap()
            .as_slice(),
        b"payload"
    );
}

// RFC 8032, section 7.1, test 2, for Ed25519.
#[test]
fn ed25519_rfc8032() {
    let p = p();
    let key = p
        .import_signing_key(&hex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        ))
        .unwrap();
    assert_eq!(
        to_hex(&key.public_key().key),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );
    let signature = key.sign(&[0x72]).unwrap();
    assert_eq!(
        to_hex(&signature),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    );
    p.verify(key.public_key(), &[0x72], &signature).unwrap();
    assert!(p.verify(key.public_key(), &[0x73], &signature).is_err());
}

// RFC 7748, section 6.1, for X25519.
#[test]
fn x25519_rfc7748() {
    let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = p()
        .kex_agree(crypto_provider::suite::KEX_X25519, &alice, &bob_public)
        .unwrap();
    assert_eq!(
        to_hex(&shared),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
}

#[test]
fn x25519_rejects_small_order_share() {
    let own = [1u8; 32];
    assert_eq!(
        p().kex_agree(crypto_provider::suite::KEX_X25519, &own, &[0u8; 32])
            .unwrap_err(),
        CryptoError::Verification
    );
}

#[test]
fn ml_kem_768_round_trip_and_length_checks() {
    use crypto_provider::suite::KEX_ML_KEM_768 as KEM;
    let p = p();
    let (own, share) = p.kex_keygen(KEM).unwrap();
    assert_eq!(share.len(), 1184);
    let (ct, shared) = p.kex_respond(KEM, &share).unwrap();
    assert_eq!(ct.len(), 1088);
    assert_eq!(
        p.kex_agree(KEM, &own, &ct).unwrap().as_slice(),
        shared.as_slice()
    );
    assert!(p.kex_respond(KEM, &share[1..]).is_err());
    assert!(p.kex_agree(KEM, &own, &ct[1..]).is_err());
    // An encapsulation key whose coefficients are out of range fails the FIPS 203 check.
    assert!(p.kex_respond(KEM, &vec![0xff; 1184]).is_err());
}

#[test]
fn key_wrap_round_trip_and_tamper() {
    let p = p();
    let kek = AeadKey {
        enc: secret(&[4u8; 32]),
        mac: secret(&[6u8; 32]),
    };
    let mut wrapped = p.key_wrap(&kek, b"secret key material").unwrap();
    assert_eq!(
        p.key_unwrap(&kek, &wrapped).unwrap().as_slice(),
        b"secret key material"
    );
    wrapped[0] ^= 1;
    assert!(p.key_unwrap(&kek, &wrapped).is_err());
}

#[test]
fn seeded_random_is_reproducible() {
    let (a, b) = (
        TestOnlyProvider::seeded(b"seed"),
        TestOnlyProvider::seeded(b"seed"),
    );
    let (mut x, mut y) = ([0u8; 100], [0u8; 100]);
    a.random(&mut x).unwrap();
    b.random(&mut y).unwrap();
    assert_eq!(x, y);
    a.random(&mut y).unwrap();
    assert_ne!(x, y);
}

#[test]
fn offers_only_the_test_only_range() {
    for suite in p().suites() {
        assert!(crypto_provider::suite::is_test_only(*suite));
    }
}

// The keystream is AES-256-CTR with a 32-bit big-endian block counter starting at
// 0. Checked against an independently computed vector (openssl enc -aes-256-ctr).
#[test]
fn keystream_matches_openssl() {
    let p = p();
    let key = AeadKey {
        enc: secret(&hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )),
        mac: secret(&[0u8; 32]),
    };
    let nonce = hex("f0f1f2f3f4f5f6f7f8f9fafb");
    let plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    let sealed = p.aead_seal(&key, &nonce, b"", &plaintext).unwrap();
    assert_eq!(to_hex(&sealed[..32]), EXPECTED_CTR);
}

const EXPECTED_CTR: &str = "c93972439eff79604668294c3e0241cebe964936b5bbb2f945b9c846324f4d54";
