//! A timing check in the style of dudect: Welch's t-test between two input classes.
//!
//! Timing on a shared machine is noisy, so this is `#[ignore]`d in the normal test run
//! and run on demand. It measures this provider's HMAC comparison, and the harness is
//! what matters: `provider-<lib>` must pass the same check, because the library's
//! constant-time status is a question in `docs/crypto-inventory.md`.
//!
//! ```text
//! cargo test -p provider-testonly --test timing -- --ignored --nocapture
//! ```

use crypto_provider::{AeadKey, CryptoProvider, ct_eq, secret};
use provider_testonly::TestOnlyProvider;
use std::hint::black_box;
use std::time::Instant;

/// Beyond this |t|, the two classes are told apart with overwhelming confidence.
const T_THRESHOLD: f64 = 10.0;

#[derive(Default)]
struct Welch {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Welch {
    fn add(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }
    fn var(&self) -> f64 {
        self.m2 / (self.n - 1.0)
    }
}

fn t_statistic(a: &Welch, b: &Welch) -> f64 {
    (a.mean - b.mean) / (a.var() / a.n + b.var() / b.n).sqrt()
}

/// Picks the class at random for each sample, as dudect does, because a fixed order
/// makes ordering effects look like a leak. `prepare` sets up the input outside the
/// timed part, so both classes use the same memory and differ only in its contents.
/// Drops the slowest samples, which are mostly interrupts.
fn measure(rounds: usize, mut prepare: impl FnMut(bool), mut operation: impl FnMut()) -> f64 {
    let mut samples: Vec<(bool, f64)> = Vec::with_capacity(rounds * 2);
    let mut random = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..rounds * 2 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let is_a = random & 1 == 0;
        prepare(is_a);
        let start = Instant::now();
        operation();
        samples.push((is_a, start.elapsed().as_nanos() as f64));
    }
    let mut sorted: Vec<f64> = samples.iter().map(|s| s.1).collect();
    sorted.sort_by(f64::total_cmp);
    let cutoff = sorted[sorted.len() * 95 / 100];
    let (mut a, mut b) = (Welch::default(), Welch::default());
    for (is_a, x) in samples {
        if x <= cutoff {
            if is_a { a.add(x) } else { b.add(x) }
        }
    }
    let t = t_statistic(&a, &b);
    println!("  means: {:.1} ns and {:.1} ns", a.mean, b.mean);
    t
}

/// Runs `operation` over one buffer, which differs from `base` at `first` or at `second`.
fn compare_positions(
    base: &[u8],
    first: usize,
    second: usize,
    rounds: usize,
    operation: impl Fn(&[u8]),
) -> f64 {
    let probe = std::cell::RefCell::new(base.to_vec());
    measure(
        rounds,
        |is_first| {
            let mut probe = probe.borrow_mut();
            probe.copy_from_slice(base);
            probe[if is_first { first } else { second }] ^= 1;
        },
        || operation(&probe.borrow()),
    )
}

#[test]
#[ignore = "timing is noisy on a shared machine. Run on demand."]
fn tag_comparison_does_not_depend_on_where_the_bytes_differ() {
    let expected = vec![0x5Au8; 32];
    let t = compare_positions(&expected, 0, 31, 200_000, |probe| {
        black_box(ct_eq(&expected, black_box(probe)));
    });
    println!("ct_eq: |t| = {:.2} (threshold {T_THRESHOLD})", t.abs());
    assert!(
        t.abs() < T_THRESHOLD,
        "ct_eq leaks where the first difference is: t = {t}"
    );
}

#[test]
#[ignore = "timing is noisy on a shared machine. Run on demand."]
fn a_failed_open_does_not_depend_on_where_the_tag_differs() {
    let p = TestOnlyProvider::new();
    let key = AeadKey {
        enc: secret(&[1; 32]),
        mac: secret(&[2; 32]),
    };
    let nonce = [0u8; 12];
    let sealed = p.aead_seal(&key, &nonce, b"aad", &[0u8; 256]).unwrap();
    let tag_start = sealed.len() - 32;
    let t = compare_positions(&sealed, tag_start, sealed.len() - 1, 20_000, |probe| {
        black_box(p.aead_open(&key, &nonce, b"aad", black_box(probe)).is_err());
    });
    println!("aead_open: |t| = {:.2} (threshold {T_THRESHOLD})", t.abs());
    assert!(
        t.abs() < T_THRESHOLD,
        "aead_open leaks where the tag differs: t = {t}"
    );
}

/// A control: two identical classes must not be told apart, or a failure above would
/// mean nothing.
#[test]
#[ignore = "timing is noisy on a shared machine. Run on demand."]
fn the_harness_does_not_invent_a_leak() {
    let expected = vec![0x5Au8; 32];
    let t = compare_positions(&expected, 7, 7, 200_000, |probe| {
        black_box(ct_eq(&expected, black_box(probe)));
    });
    println!(
        "identical classes: |t| = {:.2} (threshold {T_THRESHOLD})",
        t.abs()
    );
    assert!(
        t.abs() < T_THRESHOLD,
        "the harness reports a leak between identical inputs: t = {t}"
    );
}

/// A control: the harness must see an obvious leak, or a pass above would mean nothing.
#[test]
#[ignore = "timing is noisy on a shared machine. Run on demand."]
fn the_harness_detects_a_naive_comparison() {
    fn naive(a: &[u8], b: &[u8]) -> bool {
        for (x, y) in a.iter().zip(b) {
            if x != y {
                return false;
            }
        }
        true
    }
    let expected = vec![0x5Au8; 4096];
    let t = compare_positions(&expected, 0, 4095, 20_000, |probe| {
        black_box(naive(&expected, black_box(probe)));
    });
    println!("naive comparison: |t| = {:.2}", t.abs());
    assert!(
        t.abs() > T_THRESHOLD,
        "the harness cannot see even a naive comparison"
    );
}
