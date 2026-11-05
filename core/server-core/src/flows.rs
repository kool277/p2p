//! The server's control-plane behaviour, one `async` function per flow.

use crate::policy::{Policy, operation as policy_op};
use crate::records::{DeviceRecord, EnrollmentToken, PolicyRecord, UserRecord};
use crate::{
    Effect, Inner, PendingStore, Severity, State, StoreKind, StoreOperation, audit_event,
    serials_from_crl,
};
use crypto_ext::argon2id;
use crypto_provider::{from_hex, to_hex};
use qalqon_audit::{AuditEntry, operation as audit_op, secret_digest};
use qalqon_core::ErrorCode;
use qalqon_core::cert::{self, CertFields, Certificate, role};
use qalqon_core::control::{ControlMessage, RelayGrant, encode_grants, field, kind};
use qalqon_core::crl::Crl;
use qalqon_core::relay;
use qalqon_core::schedule::ctx;
use qalqon_core::wire::reason;
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

const RENDEZVOUS_TTL_MS: u64 = 120_000;
const RELAY_GRANT_TTL_MS: u64 = 300_000;
const CRL_VALIDITY_MS: u64 = 24 * 60 * 60 * 1000;
const CRL_REFRESH_MS: u64 = 12 * 60 * 60 * 1000;
const LEAF_VALIDITY_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MIN_PASSWORD_LEN: usize = 12;
const MAX_FAILED_LOGINS: u32 = 5;
const LOCK_MS: u64 = 15 * 60 * 1000;
const ALARM_FAILED_LOGINS: u32 = 3;
const MAX_PASSWORD_JOBS: u32 = 16;
const ADDRESS_TOKENS_PER_SECOND: f64 = 20.0;
const ADDRESS_BURST: f64 = 100.0;
const POLICY_NAME: &str = "default";
const CRL_RECORD: &str = "crl";

// ------------------------------------------------------------------ store access

fn store_op(
    inner: &Arc<Inner>,
    store: StoreKind,
    operation: StoreOperation,
    key: Option<String>,
    record: Option<Vec<u8>>,
) -> impl Future<Output = Result<Option<Vec<u8>>, ErrorCode>> + Send + 'static {
    let inner = inner.clone();
    let effect_id = {
        let mut state = inner.lock();
        let effect_id = state.next_effect;
        state.next_effect += 1;
        state.pending.insert(
            effect_id,
            PendingStore {
                result: None,
                waker: None,
            },
        );
        state.effects.push_back(Effect::Store {
            effect_id,
            store,
            operation,
            key,
            record,
        });
        effect_id
    };
    inner.executor.notify();
    poll_fn(move |cx| {
        let mut state = inner.lock();
        if state.shut_down {
            return Poll::Ready(Err(ErrorCode::Closed));
        }
        let Some(pending) = state.pending.get_mut(&effect_id) else {
            return Poll::Ready(Err(ErrorCode::Internal));
        };
        match pending.result.take() {
            Some(result) => {
                state.pending.remove(&effect_id);
                Poll::Ready(result)
            }
            None => {
                pending.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    })
}

async fn get_json<T: serde::de::DeserializeOwned>(
    inner: &Arc<Inner>,
    store: StoreKind,
    key: &str,
) -> Result<Option<T>, ErrorCode> {
    match store_op(inner, store, StoreOperation::Get, Some(key.into()), None).await? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| ErrorCode::Internal),
        None => Ok(None),
    }
}

async fn put_json<T: serde::Serialize>(
    inner: &Arc<Inner>,
    store: StoreKind,
    key: &str,
    value: &T,
) -> Result<(), ErrorCode> {
    let bytes = serde_json::to_vec(value).map_err(|_| ErrorCode::Internal)?;
    store_op(
        inner,
        store,
        StoreOperation::Put,
        Some(key.into()),
        Some(bytes),
    )
    .await
    .map(drop)
}

async fn list_json<T: serde::de::DeserializeOwned>(
    inner: &Arc<Inner>,
    store: StoreKind,
    key: Option<String>,
) -> Result<Vec<T>, ErrorCode> {
    match store_op(inner, store, StoreOperation::List, key, None).await? {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Internal),
        None => Ok(Vec::new()),
    }
}

// ------------------------------------------------------------------ audit

/// Only one append runs at a time, because each entry follows from the one before.
async fn audit_lock(inner: &Arc<Inner>) {
    let inner = inner.clone();
    poll_fn(move |cx| {
        let mut state = inner.lock();
        if state.audit_locked {
            state.audit_waiters.push_back(cx.waker().clone());
            Poll::Pending
        } else {
            state.audit_locked = true;
            Poll::Ready(())
        }
    })
    .await
}

fn audit_unlock(inner: &Arc<Inner>) {
    let waiter = {
        let mut state = inner.lock();
        state.audit_locked = false;
        state.audit_waiters.pop_front()
    };
    if let Some(waiter) = waiter {
        waiter.wake();
    }
}

fn raise_alarm(state: &mut State, severity: Severity, summary: String) {
    state.counters.alarms += 1;
    state.effects.push_back(Effect::Alarm { severity, summary });
}

/// Appends an audit row. If the store fails, the operation being audited must not
/// happen, so this returns `auditUnavailable` and raises an alarm.
pub(crate) async fn audit(
    inner: &Arc<Inner>,
    subject: String,
    object: String,
    operation: String,
    result: String,
    detail: String,
) -> Result<(), ErrorCode> {
    audit_lock(inner).await;
    let entry: AuditEntry = {
        let state = inner.lock();
        let event = audit_event(state.now_ms, subject, object, operation, result, detail);
        state.audit.prepare(inner.provider.as_ref(), event)
    };
    let written = match serde_json::to_vec(&entry) {
        Ok(bytes) => {
            store_op(
                inner,
                StoreKind::Audit,
                StoreOperation::Append,
                Some(entry.seq.to_string()),
                Some(bytes),
            )
            .await
        }
        Err(_) => Err(ErrorCode::Internal),
    };
    let outcome = match written {
        Ok(_) => {
            let mut state = inner.lock();
            state.audit.commit(&entry).map_err(|_| ErrorCode::Internal)
        }
        Err(_) => {
            let mut state = inner.lock();
            raise_alarm(
                &mut state,
                Severity::Critical,
                "the audit log cannot be written".into(),
            );
            Err(ErrorCode::AuditUnavailable)
        }
    };
    audit_unlock(inner);
    inner.executor.notify();
    outcome
}

pub(crate) async fn audit_only(
    inner: Arc<Inner>,
    subject: String,
    object: String,
    operation: String,
    result: String,
    detail: String,
) {
    let _ = audit(&inner, subject, object, operation, result, detail).await;
}

// ------------------------------------------------------------------ startup

/// Loads the stores, resumes the audit chain and declares the core ready.
pub(crate) async fn startup(inner: Arc<Inner>) {
    let outcome = startup_steps(&inner).await;
    let mut state = inner.lock();
    match outcome {
        Ok(()) => {
            state.ready = true;
            state.not_ready_reason.clear();
        }
        Err(code) => {
            state.not_ready_reason = format!("startup failed: {}", code.name());
            raise_alarm(&mut state, Severity::Critical, state_reason(code));
        }
    }
    drop(state);
    inner.executor.notify();
}

fn state_reason(code: ErrorCode) -> String {
    format!("the server core could not start: {}", code.name())
}

async fn startup_steps(inner: &Arc<Inner>) -> Result<(), ErrorCode> {
    // Resume the audit chain from its last row, so a restart cannot fork it.
    if let Some(bytes) = store_op(inner, StoreKind::Audit, StoreOperation::Head, None, None).await?
    {
        let entry: AuditEntry = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Internal)?;
        let head = from_hex(&entry.entry_hash).ok_or(ErrorCode::Internal)?;
        let mut state = inner.lock();
        state.audit = qalqon_audit::AuditChain::resume(head, entry.seq);
    }
    audit(
        inner,
        "server".into(),
        "server".into(),
        audit_op::SERVER_START.into(),
        "ok".into(),
        String::new(),
    )
    .await?;

    // The policy document, created on first start.
    match get_json::<PolicyRecord>(inner, StoreKind::Policy, POLICY_NAME).await? {
        Some(record) => {
            let policy: Policy =
                serde_json::from_value(record.document).map_err(|_| ErrorCode::Internal)?;
            inner.lock().policy = policy;
        }
        None => {
            let now = inner.lock().now_ms;
            let record = PolicyRecord {
                name: POLICY_NAME.into(),
                version: 1,
                document: inner.initial_policy.clone(),
                updated_at: now,
            };
            put_json(inner, StoreKind::Policy, POLICY_NAME, &record).await?;
        }
    }

    // Revocations survive a restart.
    let devices: Vec<DeviceRecord> = list_json(inner, StoreKind::Device, None).await?;
    {
        let mut state = inner.lock();
        for device in devices.iter().filter(|d| d.status == "revoked") {
            if let Some(serial) =
                from_hex(&device.serial).and_then(|s| <[u8; 16]>::try_from(s).ok())
            {
                state.revoked.insert(serial);
            }
        }
    }
    if inner.issuing.is_some() {
        sign_and_store_crl(inner).await?;
    }
    Ok(())
}

fn issuer_key_id(inner: &Inner) -> Result<[u8; 16], ErrorCode> {
    let issuing = inner.issuing.as_ref().ok_or(ErrorCode::Unsupported)?;
    let encoded =
        cert::encode_public_key(issuing.key.public_key()).map_err(|_| ErrorCode::Internal)?;
    Ok(cert::key_id(inner.provider.as_ref(), &encoded))
}

async fn sign_and_store_crl(inner: &Arc<Inner>) -> Result<(), ErrorCode> {
    let issuing = inner.issuing.as_ref().ok_or(ErrorCode::Unsupported)?;
    let raw = {
        let state = inner.lock();
        // this_update must move forward, even twice in one millisecond, because a
        // client rejects an older CRL and two CRLs at one time could differ.
        let this_update = state.now_ms.max(state.crl_this_update + 1);
        let crl = Crl {
            issuer_key_id: issuer_key_id(inner)?,
            this_update,
            next_update: this_update + CRL_VALIDITY_MS,
            revoked: state.revoked.iter().copied().collect(),
        };
        crl.sign(inner.provider.as_ref(), issuing.key.as_ref())
            .map_err(|_| ErrorCode::Internal)?
    };
    let verified = Crl::verify(inner.provider.as_ref(), issuing.key.public_key(), &raw)
        .map_err(|_| ErrorCode::Internal)?;
    let record = json!({ "crl": to_hex(&raw) });
    let record = PolicyRecord {
        name: CRL_RECORD.into(),
        version: verified.this_update,
        document: record,
        updated_at: verified.this_update,
    };
    put_json(inner, StoreKind::Policy, CRL_RECORD, &record).await?;
    let mut state = inner.lock();
    state.crl = Some(raw);
    state.crl_this_update = verified.this_update;
    state.crl_next_refresh = verified.this_update + CRL_REFRESH_MS;
    state.revoked.extend(serials_from_crl(&verified));
    Ok(())
}

pub(crate) async fn publish_crl(inner: Arc<Inner>) {
    if let Err(code) = sign_and_store_crl(&inner).await {
        let mut state = inner.lock();
        raise_alarm(
            &mut state,
            Severity::Warning,
            format!("the CRL could not be refreshed: {}", code.name()),
        );
    }
}

// ------------------------------------------------------------------ helpers

/// Moves a session's queued frames to effects. Called after anything touches a session.
pub(crate) fn flush_connection(inner: &Arc<Inner>, conn_id: u64) {
    let mut state = inner.lock();
    let Some(conn) = state.conns.get_mut(&conn_id) else {
        return;
    };
    let mut frames = Vec::new();
    while let Some(frame) = conn.session.poll_transmit() {
        frames.push(frame);
    }
    for frame in frames {
        state
            .effects
            .push_back(Effect::SendFrame { conn_id, frame });
    }
    drop(state);
    inner.executor.notify();
}

fn send_control(inner: &Arc<Inner>, conn_id: u64, message: &ControlMessage) {
    let Ok(body) = message.encode() else { return };
    {
        let mut state = inner.lock();
        let now = state.now_ms;
        let Some(conn) = state.conns.get_mut(&conn_id) else {
            return;
        };
        if conn.session.send_control(now, &body).is_err() {
            return;
        }
    }
    flush_connection(inner, conn_id);
}

/// A token bucket per address, for login, enrolment and connection attempts.
pub(crate) fn take_address_token(state: &mut State, address: &str, now_ms: u64) -> bool {
    // The port is not part of who is asking.
    let host = address
        .rsplit_once(':')
        .map_or(address, |(h, _)| h)
        .to_string();
    let (tokens, last) = state
        .addr_buckets
        .entry(host)
        .or_insert((ADDRESS_BURST, now_ms));
    let elapsed = now_ms.saturating_sub(*last) as f64 / 1000.0;
    *tokens = (*tokens + elapsed * ADDRESS_TOKENS_PER_SECOND).min(ADDRESS_BURST);
    *last = now_ms;
    if *tokens >= 1.0 {
        *tokens -= 1.0;
        true
    } else {
        false
    }
}

fn token_hash(inner: &Inner, token: &[u8]) -> String {
    let mut input = ctx("enrollment token");
    input.extend_from_slice(token);
    to_hex(&inner.provider.hash(&input))
}

fn random_hex(inner: &Inner, bytes: usize) -> Result<String, ErrorCode> {
    let mut out = vec![0u8; bytes];
    inner
        .provider
        .random(&mut out)
        .map_err(|_| ErrorCode::Internal)?;
    Ok(to_hex(&out))
}

/// Runs Argon2id off the host's threads. A job count bounds the memory an attacker can
/// make the server commit.
async fn verify_password(
    inner: &Arc<Inner>,
    password: Vec<u8>,
    stored: String,
) -> Result<bool, ErrorCode> {
    run_password_job(inner, move || {
        let result = argon2id::verify(&password, &stored);
        let mut password = password;
        crypto_provider::Zeroize::zeroize(&mut password);
        result.map_err(|_| ErrorCode::Internal)
    })
    .await
}

async fn hash_password(inner: &Arc<Inner>, password: Vec<u8>) -> Result<String, ErrorCode> {
    let mut salt = [0u8; 16];
    inner
        .provider
        .random(&mut salt)
        .map_err(|_| ErrorCode::Internal)?;
    let cost = inner.password_cost;
    run_password_job(inner, move || {
        let result = argon2id::hash(&password, &salt, cost);
        let mut password = password;
        crypto_provider::Zeroize::zeroize(&mut password);
        result.map_err(|_| ErrorCode::Internal)
    })
    .await
}

async fn run_password_job<T: Send + 'static>(
    inner: &Arc<Inner>,
    job: impl FnOnce() -> Result<T, ErrorCode> + Send + 'static,
) -> Result<T, ErrorCode> {
    {
        let mut state = inner.lock();
        if state.password_jobs >= MAX_PASSWORD_JOBS {
            return Err(ErrorCode::RateLimited);
        }
        state.password_jobs += 1;
    }
    let slot = Arc::new(std::sync::Mutex::new((None, None::<std::task::Waker>)));
    let writer = slot.clone();
    let done_inner = inner.clone();
    std::thread::spawn(move || {
        let result = job();
        let waker = {
            let mut guard = writer.lock().unwrap_or_else(|e| e.into_inner());
            guard.0 = Some(result);
            guard.1.take()
        };
        done_inner.lock().password_jobs -= 1;
        if let Some(waker) = waker {
            waker.wake();
        }
    });
    poll_fn(move |cx| {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        match guard.0.take() {
            Some(result) => Poll::Ready(result),
            None => {
                guard.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    })
    .await
}

/// Hashes against a real stored value when the user does not exist, so the time taken
/// does not reveal which users exist. Computed once per process and cached in spirit by
/// using the cheapest legal parameters of the configured cost.
fn dummy_stored_hash(inner: &Inner) -> String {
    let cost = inner.password_cost;
    format!(
        "{}${}${}${}${}",
        cost.m_kib,
        cost.t,
        cost.p,
        "00".repeat(16),
        "00".repeat(32)
    )
}

// ------------------------------------------------------------------ control messages

pub(crate) async fn control(inner: Arc<Inner>, conn_id: u64, message: ControlMessage) {
    let outcome = dispatch(&inner, conn_id, &message).await;
    if outcome.is_err() {
        // A malformed or forbidden control message ends the session with a generic
        // error. Specific refusals have already been answered with a status.
        let mut state = inner.lock();
        let now = state.now_ms;
        if let Some(conn) = state.conns.get_mut(&conn_id) {
            conn.session.close(now, reason::PROTOCOL_ERROR);
        }
        drop(state);
    }
    flush_connection(&inner, conn_id);
}

async fn dispatch(
    inner: &Arc<Inner>,
    conn_id: u64,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let (peer, user) = {
        let state = inner.lock();
        let conn = state.conns.get(&conn_id).ok_or(ErrorCode::Closed)?;
        (
            conn.peer.clone().ok_or(ErrorCode::InvalidState)?,
            conn.user.clone(),
        )
    };

    // Section 11.6: a pre-enrolment session may only enrol and fetch the CRL.
    if peer.role == role::PRE_ENROLMENT
        && !matches!(message.kind, kind::ENROLL_REQUEST | kind::CRL_REQUEST)
    {
        return Err(ErrorCode::AccessDenied);
    }

    match message.kind {
        kind::ENROLL_REQUEST => enroll(inner, conn_id, &peer, message).await,
        kind::LOGIN_REQUEST => login(inner, conn_id, &peer, message).await,
        kind::CRL_REQUEST => {
            let crl = inner.lock().crl.clone().ok_or(ErrorCode::Unsupported)?;
            send_control(
                inner,
                conn_id,
                &ControlMessage::new(kind::CRL_RESPONSE).with(field::CRL, &crl),
            );
            Ok(())
        }
        kind::RENDEZVOUS_OPEN => {
            let user = user.ok_or(ErrorCode::AccessDenied)?;
            rendezvous_open(inner, conn_id, &user, &peer, message).await
        }
        kind::RENDEZVOUS_ACCEPT => {
            user.ok_or(ErrorCode::AccessDenied)?;
            rendezvous_accept(inner, conn_id, &peer, message)
        }
        kind::RENDEZVOUS_REJECT => {
            user.ok_or(ErrorCode::AccessDenied)?;
            rendezvous_reject(inner, conn_id, message)
        }
        kind::PEER_SIGNAL => {
            user.ok_or(ErrorCode::AccessDenied)?;
            peer_signal(inner, conn_id, message)
        }
        kind::CERT_RENEW_REQUEST => {
            let user = user.ok_or(ErrorCode::AccessDenied)?;
            renew(inner, conn_id, &user, &peer).await
        }
        kind::SESSION_REPORT => {
            user.ok_or(ErrorCode::AccessDenied)?;
            session_report(inner, message)
        }
        // Anything a client has no business sending.
        _ => Err(ErrorCode::InvalidArgument),
    }
}

fn status_message(result_kind: u16, code: ErrorCode) -> ControlMessage {
    ControlMessage::new(result_kind).with_u16(field::STATUS, code.code() as u16)
}

fn parse_certificate_key(
    inner: &Inner,
    peer: &qalqon_core::PeerInfo,
) -> Result<Certificate, ErrorCode> {
    let certs =
        cert::parse_many(inner.provider.as_ref(), &peer.chain).map_err(|_| ErrorCode::Internal)?;
    certs.into_iter().next().ok_or(ErrorCode::Internal)
}

fn issue_device_chain(
    inner: &Inner,
    user_id: &str,
    device_id: &str,
    sign_public: crypto_provider::PublicKey,
    now_ms: u64,
) -> Result<(Vec<u8>, [u8; 16], u64), ErrorCode> {
    let issuing = inner.issuing.as_ref().ok_or(ErrorCode::Unsupported)?;
    let p = inner.provider.as_ref();
    let serial = cert::random_serial(p).map_err(|_| ErrorCode::Internal)?;
    let not_after = now_ms + LEAF_VALIDITY_MS;
    let mut chain = cert::issue(
        p,
        issuing.key.as_ref(),
        &CertFields {
            serial,
            role: role::DEVICE,
            subject_a: user_id.into(),
            subject_b: device_id.into(),
            not_before: now_ms.saturating_sub(5 * 60 * 1000),
            not_after,
            sign_public,
            issuer_key_id: issuer_key_id(inner)?,
        },
    )
    .map_err(|_| ErrorCode::Internal)?;
    chain.extend_from_slice(&issuing.certificate);
    Ok((chain, serial, not_after))
}

async fn enroll(
    inner: &Arc<Inner>,
    conn_id: u64,
    peer: &qalqon_core::PeerInfo,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let token = message
        .get(field::TOKEN)
        .ok_or(ErrorCode::InvalidArgument)?;
    let device_name = message
        .get_str(field::DEVICE_NAME)
        .ok_or(ErrorCode::InvalidArgument)?
        .to_string();
    let reject = |inner: &Arc<Inner>| {
        send_control(
            inner,
            conn_id,
            &status_message(kind::ENROLL_RESULT, ErrorCode::EnrollmentRejected),
        );
    };

    let (now, allowed, remote) = {
        let mut state = inner.lock();
        let now = state.now_ms;
        let remote = state
            .conns
            .get(&conn_id)
            .map(|c| c.remote.clone())
            .unwrap_or_default();
        (now, take_address_token(&mut state, &remote, now), remote)
    };
    if !allowed {
        send_control(
            inner,
            conn_id,
            &status_message(kind::ENROLL_RESULT, ErrorCode::RateLimited),
        );
        return Ok(());
    }

    // A token is <user_id>:<random>. The hash is compared, so the store holds no token.
    let text = std::str::from_utf8(token).map_err(|_| ErrorCode::InvalidArgument)?;
    let Some((user_id, _)) = text.split_once(':') else {
        reject(inner);
        return Ok(());
    };
    let hash = token_hash(inner, token);
    let Some(mut user) = get_json::<UserRecord>(inner, StoreKind::User, user_id).await? else {
        audit(
            inner,
            remote,
            user_id.into(),
            audit_op::ENROLLMENT.into(),
            ErrorCode::EnrollmentRejected.name().into(),
            String::new(),
        )
        .await?;
        reject(inner);
        return Ok(());
    };
    let position = user.enrollment_tokens.iter().position(|t| {
        crypto_provider::ct_eq(t.hash.as_bytes(), hash.as_bytes()) && t.expires_at > now
    });
    let allowed = {
        let state = inner.lock();
        state.policy.allows(
            &user.user_id,
            &user.role,
            policy_op::ENROLL,
            &format!("user:{}", user.user_id),
        )
    };
    let (Some(position), true, "active") = (position, allowed, user.status.as_str()) else {
        audit(
            inner,
            remote,
            user_id.into(),
            audit_op::ENROLLMENT.into(),
            ErrorCode::EnrollmentRejected.name().into(),
            String::new(),
        )
        .await?;
        reject(inner);
        return Ok(());
    };

    let leaf = parse_certificate_key(inner, peer)?;
    let device_id = random_hex(inner, 8)?;
    let (chain, serial, _) = issue_device_chain(
        inner,
        &user.user_id,
        &device_id,
        leaf.fields.sign_public.clone(),
        now,
    )?;
    let record = DeviceRecord {
        device_id: device_id.clone(),
        user_id: user.user_id.clone(),
        device_name,
        fingerprint: to_hex(&peer.fingerprint),
        cert_chain: to_hex(&chain),
        serial: to_hex(&serial),
        status: "active".into(),
        enrolled_at: now,
        revoked_at: None,
        last_seen_at: None,
    };

    // The token is consumed first, so a failure further on cannot leave it reusable.
    user.enrollment_tokens.remove(position);
    user.updated_at = now;
    put_json(inner, StoreKind::User, &user.user_id, &user).await?;
    audit(
        inner,
        user.user_id.clone(),
        device_id.clone(),
        audit_op::ENROLLMENT.into(),
        "ok".into(),
        to_hex(&peer.fingerprint),
    )
    .await?;
    put_json(inner, StoreKind::Device, &device_id, &record).await?;

    send_control(
        inner,
        conn_id,
        &status_message(kind::ENROLL_RESULT, ErrorCode::Ok).with(field::CHAIN, &chain),
    );
    Ok(())
}

async fn login(
    inner: &Arc<Inner>,
    conn_id: u64,
    peer: &qalqon_core::PeerInfo,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let user_id = message
        .get_str(field::USER_ID)
        .ok_or(ErrorCode::InvalidArgument)?
        .to_string();
    let secret = message
        .get(field::SECRET)
        .ok_or(ErrorCode::InvalidArgument)?
        .to_vec();
    let mfa_code = message.get_str(field::MFA_CODE).map(str::to_string);

    let reply = |code: ErrorCode, retry: Option<u32>| {
        let mut m = status_message(kind::LOGIN_RESULT, code);
        if let Some(retry) = retry {
            m = m.with_u32(field::RETRY_AFTER_MS, retry);
        }
        send_control(inner, conn_id, &m);
    };

    let (now, allowed, remote) = {
        let mut state = inner.lock();
        let now = state.now_ms;
        let remote = state
            .conns
            .get(&conn_id)
            .map(|c| c.remote.clone())
            .unwrap_or_default();
        (now, take_address_token(&mut state, &remote, now), remote)
    };
    if !allowed {
        reply(ErrorCode::RateLimited, Some(1000));
        return Ok(());
    }

    let record = get_json::<UserRecord>(inner, StoreKind::User, &user_id).await?;
    let stored = record
        .as_ref()
        .map_or_else(|| dummy_stored_hash(inner), |u| u.password_hash.clone());
    let password_ok = match verify_password(inner, secret.clone(), stored).await {
        Ok(ok) => ok,
        Err(ErrorCode::RateLimited) => {
            reply(ErrorCode::RateLimited, Some(1000));
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    // The certificate has to name the same user (section 11.3, step 4).
    let certificate_matches = peer.subject_a == user_id;

    let failure =
        |record: Option<UserRecord>, code: ErrorCode, retry: Option<u32>, detail: &'static str| {
            let inner = inner.clone();
            let secret = secret.clone();
            let user_id = user_id.clone();
            let remote = remote.clone();
            async move {
                let digest = secret_digest(inner.provider.as_ref(), &inner.audit_key, &secret);
                let mut count = 0;
                if let Some(mut user) = record {
                    user.failed_attempts += 1;
                    count = user.failed_attempts;
                    if user.failed_attempts >= MAX_FAILED_LOGINS {
                        user.locked_until = now + LOCK_MS;
                    }
                    user.updated_at = now;
                    put_json(&inner, StoreKind::User, &user.user_id, &user).await?;
                }
                {
                    let mut state = inner.lock();
                    state.counters.logins_failed += 1;
                    if count >= ALARM_FAILED_LOGINS {
                        raise_alarm(
                            &mut state,
                            Severity::Warning,
                            format!("repeated failed logins for {user_id}"),
                        );
                    }
                }
                audit(
                    &inner,
                    remote,
                    user_id,
                    audit_op::LOGIN.into(),
                    code.name().into(),
                    format!("{detail} secret_digest={digest}"),
                )
                .await?;
                let mut m = status_message(kind::LOGIN_RESULT, code);
                if let Some(retry) = retry {
                    m = m.with_u32(field::RETRY_AFTER_MS, retry);
                }
                send_control(&inner, conn_id, &m);
                Ok::<(), ErrorCode>(())
            }
        };

    let Some(mut user) = record else {
        // An unknown user is not told apart from a wrong password.
        return failure(None, ErrorCode::AuthenticationFailed, None, "unknown user").await;
    };
    if user.locked_until > now {
        let retry = u32::try_from(user.locked_until - now).unwrap_or(u32::MAX);
        return failure(Some(user), ErrorCode::RateLimited, Some(retry), "locked").await;
    }
    if !password_ok {
        return failure(
            Some(user),
            ErrorCode::AuthenticationFailed,
            None,
            "wrong secret",
        )
        .await;
    }
    if !certificate_matches {
        return failure(
            Some(user),
            ErrorCode::AuthenticationFailed,
            None,
            "certificate names another user",
        )
        .await;
    }
    if user.status != "active" {
        return failure(
            Some(user),
            ErrorCode::AuthenticationFailed,
            None,
            "disabled",
        )
        .await;
    }
    let device = get_json::<DeviceRecord>(inner, StoreKind::Device, &peer.subject_b).await?;
    let device_ok = device.as_ref().is_some_and(|d| {
        d.user_id == user.user_id
            && d.status == "active"
            && d.fingerprint == to_hex(&peer.fingerprint)
    });
    if !device_ok {
        return failure(
            Some(user),
            ErrorCode::NotEnrolled,
            None,
            "device not enrolled, or revoked",
        )
        .await;
    }
    if user.mfa_state.is_some() && mfa_code.is_none() {
        // MFA verification itself is not implemented yet. See docs/COMPLIANCE.md.
        reply(ErrorCode::MfaRequired, None);
        return Ok(());
    }
    if user.mfa_state.is_some() {
        return failure(
            Some(user),
            ErrorCode::Unsupported,
            None,
            "MFA verification is not implemented",
        )
        .await;
    }
    let allowed = {
        let state = inner.lock();
        state.policy.allows(
            &user.user_id,
            &user.role,
            policy_op::LOGIN,
            &format!("user:{}", user.user_id),
        )
    };
    if !allowed {
        return failure(
            Some(user),
            ErrorCode::AccessDenied,
            None,
            "denied by policy",
        )
        .await;
    }

    // An operation that cannot be logged does not happen.
    audit(
        inner,
        user.user_id.clone(),
        peer.subject_b.clone(),
        audit_op::LOGIN.into(),
        "ok".into(),
        remote,
    )
    .await?;

    user.failed_attempts = 0;
    user.locked_until = 0;
    user.updated_at = now;
    put_json(inner, StoreKind::User, &user.user_id, &user).await?;
    if let Some(mut device) = device {
        device.last_seen_at = Some(now);
        put_json(inner, StoreKind::Device, &device.device_id, &device).await?;
    }
    {
        let mut state = inner.lock();
        state.counters.logins_ok += 1;
        let Some(conn) = state.conns.get_mut(&conn_id) else {
            return Ok(());
        };
        conn.user = Some(crate::AuthenticatedUser {
            user_id: user.user_id.clone(),
            device_id: peer.subject_b.clone(),
            role: user.role.clone(),
        });
        state
            .online
            .entry(user.user_id.clone())
            .or_default()
            .insert(peer.subject_b.clone(), conn_id);
    }
    reply(ErrorCode::Ok, None);
    Ok(())
}

fn grants_for(inner: &Inner, rendezvous_id: &[u8; 16], now: u64) -> Result<Vec<u8>, ErrorCode> {
    let expires_at = now + RELAY_GRANT_TTL_MS;
    let token = relay::issue_token(
        inner.provider.as_ref(),
        &inner.relay_key,
        rendezvous_id,
        expires_at,
    );
    let grants: Vec<RelayGrant> = inner
        .relay_addresses
        .iter()
        .map(|address| RelayGrant {
            address: address.clone(),
            token: token.clone(),
            expires_at,
        })
        .collect();
    encode_grants(&grants).map_err(|_| ErrorCode::Internal)
}

async fn rendezvous_open(
    inner: &Arc<Inner>,
    conn_id: u64,
    user: &crate::AuthenticatedUser,
    peer: &qalqon_core::PeerInfo,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let request_id = message
        .get_id(field::REQUEST_ID)
        .ok_or(ErrorCode::InvalidArgument)?;
    let target_user = message
        .get_str(field::USER_ID)
        .ok_or(ErrorCode::InvalidArgument)?
        .to_string();
    let target_device = message.get_str(field::DEVICE_ID).map(str::to_string);
    let options = message
        .get(field::CHANNEL_OPTIONS)
        .ok_or(ErrorCode::InvalidArgument)?
        .to_vec();
    qalqon_core::control::parse_channel_options(&options)
        .map_err(|_| ErrorCode::InvalidArgument)?;

    let object = format!("user:{target_user}");
    let (allowed, target_conn, now, duplicate) = {
        let state = inner.lock();
        let allowed =
            state
                .policy
                .allows(&user.user_id, &user.role, policy_op::RENDEZVOUS, &object);
        let devices = state.online.get(&target_user);
        let target = match (&target_device, devices) {
            (Some(d), Some(devices)) => devices.get(d).copied(),
            (None, Some(devices)) => devices.values().copied().find(|c| *c != conn_id),
            _ => None,
        };
        (
            allowed,
            target,
            state.now_ms,
            state.requests.contains_key(&(conn_id, request_id)),
        )
    };
    if duplicate {
        return Err(ErrorCode::InvalidArgument);
    }

    // Whatever the reason, the caller learns only that it did not happen.
    let result = if !allowed {
        ErrorCode::AccessDenied.name()
    } else if target_conn.is_none() {
        ErrorCode::PeerUnavailable.name()
    } else {
        "ok"
    };
    audit(
        inner,
        user.user_id.clone(),
        object,
        audit_op::RENDEZVOUS.into(),
        result.into(),
        to_hex(&request_id),
    )
    .await?;
    let Some(target) = target_conn.filter(|_| allowed) else {
        send_control(
            inner,
            conn_id,
            &ControlMessage::new(kind::RENDEZVOUS_REJECT).with(field::REQUEST_ID, &request_id),
        );
        return Ok(());
    };

    let mut rendezvous_id = [0u8; 16];
    inner
        .provider
        .random(&mut rendezvous_id)
        .map_err(|_| ErrorCode::Internal)?;
    let grants = grants_for(inner, &rendezvous_id, now)?;
    {
        let mut state = inner.lock();
        state.counters.rendezvous_opened += 1;
        state.rendezvous.insert(
            rendezvous_id,
            crate::Rendezvous {
                opener: conn_id,
                target,
                id: rendezvous_id,
                accepted: false,
                expires_at: now + RENDEZVOUS_TTL_MS,
            },
        );
        state.requests.insert((conn_id, request_id), rendezvous_id);
        state.requests.insert((target, request_id), rendezvous_id);
    }
    let incoming = ControlMessage::new(kind::RENDEZVOUS_INCOMING)
        .with(field::REQUEST_ID, &request_id)
        .with(field::RENDEZVOUS_ID, &rendezvous_id)
        .with_str(field::USER_ID, &user.user_id)
        .with_str(field::DEVICE_ID, &user.device_id)
        .with(field::CHAIN, &peer.chain)
        .with(field::CHANNEL_OPTIONS, &options)
        .with(field::RELAY_GRANTS, &grants);
    send_control(inner, target, &incoming);
    Ok(())
}

fn rendezvous_accept(
    inner: &Arc<Inner>,
    conn_id: u64,
    peer: &qalqon_core::PeerInfo,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let request_id = message
        .get_id(field::REQUEST_ID)
        .ok_or(ErrorCode::InvalidArgument)?;
    let (opener, rendezvous_id, now) = {
        let mut state = inner.lock();
        let now = state.now_ms;
        let id = *state
            .requests
            .get(&(conn_id, request_id))
            .ok_or(ErrorCode::InvalidArgument)?;
        let rendezvous = state
            .rendezvous
            .get_mut(&id)
            .ok_or(ErrorCode::InvalidArgument)?;
        if rendezvous.target != conn_id || rendezvous.accepted {
            return Err(ErrorCode::InvalidState);
        }
        rendezvous.accepted = true;
        (rendezvous.opener, rendezvous.id, now)
    };
    let grants = grants_for(inner, &rendezvous_id, now)?;
    let ready = ControlMessage::new(kind::RENDEZVOUS_READY)
        .with(field::REQUEST_ID, &request_id)
        .with(field::RENDEZVOUS_ID, &rendezvous_id)
        .with(field::CHAIN, &peer.chain)
        .with(field::RELAY_GRANTS, &grants);
    send_control(inner, opener, &ready);
    Ok(())
}

fn rendezvous_reject(
    inner: &Arc<Inner>,
    conn_id: u64,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let request_id = message
        .get_id(field::REQUEST_ID)
        .ok_or(ErrorCode::InvalidArgument)?;
    let other = {
        let mut state = inner.lock();
        let id = state
            .requests
            .remove(&(conn_id, request_id))
            .ok_or(ErrorCode::InvalidArgument)?;
        let rendezvous = state
            .rendezvous
            .remove(&id)
            .ok_or(ErrorCode::InvalidArgument)?;
        let other = if rendezvous.opener == conn_id {
            rendezvous.target
        } else {
            rendezvous.opener
        };
        state.requests.remove(&(other, request_id));
        other
    };
    send_control(
        inner,
        other,
        &ControlMessage::new(kind::RENDEZVOUS_REJECT).with(field::REQUEST_ID, &request_id),
    );
    Ok(())
}

fn peer_signal(
    inner: &Arc<Inner>,
    conn_id: u64,
    message: &ControlMessage,
) -> Result<(), ErrorCode> {
    let rendezvous_id = message
        .get_id(field::RENDEZVOUS_ID)
        .ok_or(ErrorCode::InvalidArgument)?;
    let blob = message.get(field::BLOB).ok_or(ErrorCode::InvalidArgument)?;
    let other = {
        let state = inner.lock();
        let rendezvous = state
            .rendezvous
            .get(&rendezvous_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        if rendezvous.opener == conn_id {
            rendezvous.target
        } else if rendezvous.target == conn_id {
            rendezvous.opener
        } else {
            return Err(ErrorCode::AccessDenied);
        }
    };
    send_control(
        inner,
        other,
        &ControlMessage::new(kind::PEER_SIGNAL)
            .with(field::RENDEZVOUS_ID, &rendezvous_id)
            .with(field::BLOB, blob),
    );
    Ok(())
}

async fn renew(
    inner: &Arc<Inner>,
    conn_id: u64,
    user: &crate::AuthenticatedUser,
    peer: &qalqon_core::PeerInfo,
) -> Result<(), ErrorCode> {
    let now = inner.lock().now_ms;
    let allowed = {
        let state = inner.lock();
        state.policy.allows(
            &user.user_id,
            &user.role,
            policy_op::RENEW,
            &format!("user:{}", user.user_id),
        )
    };
    if !allowed {
        send_control(
            inner,
            conn_id,
            &status_message(kind::CERT_RENEW_RESULT, ErrorCode::AccessDenied),
        );
        return Ok(());
    }
    let Some(mut device) =
        get_json::<DeviceRecord>(inner, StoreKind::Device, &user.device_id).await?
    else {
        send_control(
            inner,
            conn_id,
            &status_message(kind::CERT_RENEW_RESULT, ErrorCode::NotEnrolled),
        );
        return Ok(());
    };
    let leaf = parse_certificate_key(inner, peer)?;
    let (chain, serial, _) = issue_device_chain(
        inner,
        &user.user_id,
        &user.device_id,
        leaf.fields.sign_public,
        now,
    )?;
    device.cert_chain = to_hex(&chain);
    device.serial = to_hex(&serial);
    audit(
        inner,
        user.user_id.clone(),
        user.device_id.clone(),
        audit_op::KEY_USED.into(),
        "ok".into(),
        "certificate renewed".into(),
    )
    .await?;
    put_json(inner, StoreKind::Device, &device.device_id, &device).await?;
    send_control(
        inner,
        conn_id,
        &status_message(kind::CERT_RENEW_RESULT, ErrorCode::Ok).with(field::CHAIN, &chain),
    );
    Ok(())
}

fn session_report(inner: &Arc<Inner>, message: &ControlMessage) -> Result<(), ErrorCode> {
    // Self-reported, so this feeds metrics and never feeds a security decision.
    let path = message.get(field::PATH).ok_or(ErrorCode::InvalidArgument)?;
    let mut state = inner.lock();
    match path {
        [1] => state.counters.direct_sessions += 1,
        [2] => state.counters.relayed_sessions += 1,
        _ => return Err(ErrorCode::InvalidArgument),
    }
    if let Some(counters) = message.get(field::COUNTERS)
        && counters.len() == 16
    {
        let mut records = [0u8; 8];
        let mut bytes = [0u8; 8];
        records.copy_from_slice(&counters[..8]);
        bytes.copy_from_slice(&counters[8..]);
        state.counters.reported_records += u64::from_be_bytes(records);
        state.counters.reported_bytes += u64::from_be_bytes(bytes);
    }
    Ok(())
}

// ------------------------------------------------------------------ admin

pub(crate) async fn admin(
    inner: Arc<Inner>,
    method: &str,
    params: Value,
) -> Result<String, ErrorCode> {
    let text = |key: &str| {
        params
            .get(key)
            .and_then(Value::as_str)
            .ok_or(ErrorCode::InvalidArgument)
            .map(str::to_string)
    };
    let now = inner.lock().now_ms;
    match method {
        "users.create" => {
            let user_id = text("user_id")?;
            let password = text("password")?;
            if user_id.is_empty() || user_id.contains(':') || user_id.len() > 200 {
                return Err(ErrorCode::InvalidArgument);
            }
            // The standard's floor is 8 alphanumeric characters. Build prompt §1.6 says
            // to enforce 12.
            if password.chars().count() < MIN_PASSWORD_LEN {
                return Err(ErrorCode::InvalidArgument);
            }
            if get_json::<UserRecord>(&inner, StoreKind::User, &user_id)
                .await?
                .is_some()
            {
                return Err(ErrorCode::InvalidState);
            }
            let role = params
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user")
                .to_string();
            if !matches!(role.as_str(), "user" | "admin") {
                return Err(ErrorCode::InvalidArgument);
            }
            let hash = hash_password(&inner, password.into_bytes()).await?;
            let record = UserRecord {
                display_name: params
                    .get("display_name")
                    .and_then(Value::as_str)
                    .unwrap_or(&user_id)
                    .to_string(),
                user_id: user_id.clone(),
                password_hash: hash,
                mfa_state: None,
                role: role.clone(),
                status: "active".into(),
                failed_attempts: 0,
                locked_until: 0,
                enrollment_tokens: Vec::new(),
                created_at: now,
                updated_at: now,
            };
            audit(
                &inner,
                "admin".into(),
                user_id.clone(),
                audit_op::PRIVILEGE_CHANGE.into(),
                "ok".into(),
                format!("created with role {role}"),
            )
            .await?;
            put_json(&inner, StoreKind::User, &user_id, &record).await?;
            Ok(json!({ "user_id": user_id }).to_string())
        }
        "users.list" => {
            let users: Vec<UserRecord> = list_json(&inner, StoreKind::User, None).await?;
            let view: Vec<Value> = users
                .iter()
                .map(|u| json!({ "user_id": u.user_id, "display_name": u.display_name, "role": u.role, "status": u.status }))
                .collect();
            Ok(Value::Array(view).to_string())
        }
        "users.disable" => {
            let user_id = text("user_id")?;
            let mut user = get_json::<UserRecord>(&inner, StoreKind::User, &user_id)
                .await?
                .ok_or(ErrorCode::InvalidArgument)?;
            audit(
                &inner,
                "admin".into(),
                user_id.clone(),
                audit_op::PRIVILEGE_CHANGE.into(),
                "ok".into(),
                "disabled".into(),
            )
            .await?;
            user.status = "disabled".into();
            user.updated_at = now;
            put_json(&inner, StoreKind::User, &user_id, &user).await?;
            // Sessions already logged in end now.
            let conns: Vec<u64> = inner
                .lock()
                .online
                .get(&user_id)
                .map(|d| d.values().copied().collect())
                .unwrap_or_default();
            for conn_id in conns {
                {
                    let mut state = inner.lock();
                    if let Some(conn) = state.conns.get_mut(&conn_id) {
                        conn.session.close(now, reason::REJECTED);
                    }
                }
                flush_connection(&inner, conn_id);
            }
            Ok("{}".into())
        }
        "users.resetPassword" => {
            let user_id = text("user_id")?;
            let password = text("password")?;
            if password.chars().count() < MIN_PASSWORD_LEN {
                return Err(ErrorCode::InvalidArgument);
            }
            let mut user = get_json::<UserRecord>(&inner, StoreKind::User, &user_id)
                .await?
                .ok_or(ErrorCode::InvalidArgument)?;
            user.password_hash = hash_password(&inner, password.into_bytes()).await?;
            user.failed_attempts = 0;
            user.locked_until = 0;
            user.updated_at = now;
            audit(
                &inner,
                "admin".into(),
                user_id.clone(),
                audit_op::PRIVILEGE_CHANGE.into(),
                "ok".into(),
                "password reset".into(),
            )
            .await?;
            put_json(&inner, StoreKind::User, &user_id, &user).await?;
            Ok("{}".into())
        }
        "devices.list" => {
            let filter = params
                .get("user_id")
                .and_then(Value::as_str)
                .map(|u| format!("user:{u}"));
            let devices: Vec<DeviceRecord> = list_json(&inner, StoreKind::Device, filter).await?;
            let view: Vec<Value> = devices
                .iter()
                .map(|d| json!({ "device_id": d.device_id, "user_id": d.user_id, "device_name": d.device_name, "fingerprint": d.fingerprint, "status": d.status }))
                .collect();
            Ok(Value::Array(view).to_string())
        }
        "devices.createEnrollmentToken" => {
            let user_id = text("user_id")?;
            let ttl = params
                .get("ttl_ms")
                .and_then(Value::as_u64)
                .unwrap_or(24 * 60 * 60 * 1000);
            let mut user = get_json::<UserRecord>(&inner, StoreKind::User, &user_id)
                .await?
                .ok_or(ErrorCode::InvalidArgument)?;
            let token = format!("{user_id}:{}", random_hex(&inner, 32)?);
            user.enrollment_tokens.retain(|t| t.expires_at > now);
            user.enrollment_tokens.push(EnrollmentToken {
                hash: token_hash(&inner, token.as_bytes()),
                expires_at: now + ttl,
            });
            user.updated_at = now;
            audit(
                &inner,
                "admin".into(),
                user_id.clone(),
                audit_op::KEY_GENERATED.into(),
                "ok".into(),
                "enrollment token created".into(),
            )
            .await?;
            put_json(&inner, StoreKind::User, &user_id, &user).await?;
            Ok(json!({ "token": token }).to_string())
        }
        "devices.revoke" => {
            let device_id = text("device_id")?;
            let mut device = get_json::<DeviceRecord>(&inner, StoreKind::Device, &device_id)
                .await?
                .ok_or(ErrorCode::InvalidArgument)?;
            let serial = from_hex(&device.serial)
                .and_then(|s| <[u8; 16]>::try_from(s).ok())
                .ok_or(ErrorCode::Internal)?;
            audit(
                &inner,
                "admin".into(),
                device_id.clone(),
                audit_op::REVOCATION.into(),
                "ok".into(),
                device.serial.clone(),
            )
            .await?;
            device.status = "revoked".into();
            device.revoked_at = Some(now);
            put_json(&inner, StoreKind::Device, &device_id, &device).await?;
            let conn = {
                let mut state = inner.lock();
                state.revoked.insert(serial);
                let conn = state
                    .online
                    .get(&device.user_id)
                    .and_then(|d| d.get(&device_id))
                    .copied();
                if let Some(conn_id) = conn
                    && let Some(conn) = state.conns.get_mut(&conn_id)
                {
                    conn.session.close(now, reason::REJECTED);
                }
                conn
            };
            if let Some(conn_id) = conn {
                flush_connection(&inner, conn_id);
            }
            if inner.issuing.is_some() {
                sign_and_store_crl(&inner).await?;
            }
            Ok("{}".into())
        }
        "revocation.publish" => {
            if inner.issuing.is_some() {
                sign_and_store_crl(&inner).await?;
                return Ok("{}".into());
            }
            Err(ErrorCode::Unsupported)
        }
        "audit.export" => {
            let from = params.get("from").and_then(Value::as_u64).unwrap_or(1);
            let to = params.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let entries: Vec<AuditEntry> = match store_op(
                &inner,
                StoreKind::Audit,
                StoreOperation::Range,
                Some(format!("{from},{to}")),
                None,
            )
            .await?
            {
                Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Internal)?,
                None => Vec::new(),
            };
            let checkpoint = {
                let state = inner.lock();
                state
                    .audit
                    .checkpoint(inner.identity.as_ref())
                    .map_err(|_| ErrorCode::Internal)?
            };
            Ok(json!({ "entries": entries, "checkpoint": checkpoint }).to_string())
        }
        "audit.verify" => {
            let entries: Vec<AuditEntry> = match store_op(
                &inner,
                StoreKind::Audit,
                StoreOperation::Range,
                Some(format!("1,{}", u64::MAX)),
                None,
            )
            .await?
            {
                Some(bytes) => serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Internal)?,
                None => Vec::new(),
            };
            let encoded = cert::encode_public_key(inner.identity.public_key())
                .map_err(|_| ErrorCode::Internal)?;
            let fingerprint = cert::fingerprint(inner.provider.as_ref(), &encoded);
            let (ok, detail) =
                match qalqon_audit::verify_chain(inner.provider.as_ref(), &fingerprint, &entries) {
                    Ok(head) => {
                        let state = inner.lock();
                        if head == state.audit.head() && entries.len() as u64 == state.audit.seq() {
                            (true, String::new())
                        } else {
                            (
                                false,
                                "the stored rows stop short of the chain head".to_string(),
                            )
                        }
                    }
                    Err(e) => (false, e.to_string()),
                };
            if !ok {
                let mut state = inner.lock();
                raise_alarm(
                    &mut state,
                    Severity::Critical,
                    format!("the audit chain does not verify: {detail}"),
                );
            }
            Ok(json!({ "ok": ok, "entries": entries.len(), "detail": detail }).to_string())
        }
        _ => Err(ErrorCode::InvalidArgument),
    }
}
