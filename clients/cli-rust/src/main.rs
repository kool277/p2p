//! A command-line client. Events are printed as JSON Lines, so a test can read them.
//!
//! ```text
//! qalqon-cli-rust enroll --server <url> --ca <hex file> --data <dir> --token <token>
//! qalqon-cli-rust call   --server <url> --ca <hex file> --data <dir> --user <id> --peer <id> [--records N] [--relay-only]
//! qalqon-cli-rust answer --server <url> --ca <hex file> --data <dir> --user <id> [--relay-only] [--wait-ms N]
//! ```
//!
//! The password comes from the `QALQON_PASSWORD` environment variable, never from an
//! argument, because arguments are visible to every process on the machine.

use qalqon_sdk::api;
use serde_json::json;
use std::time::{Duration, Instant};

fn value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn required(args: &[String], flag: &str) -> Result<String, String> {
    value(args, flag).ok_or_else(|| format!("{flag} is required"))
}

fn config(args: &[String]) -> Result<api::SessionConfig, String> {
    let ca = std::fs::read_to_string(required(args, "--ca")?).map_err(|e| format!("--ca: {e}"))?;
    let relay_policy = if args.iter().any(|a| a == "--relay-only") {
        Some(api::RelayPolicy::RelayOnly)
    } else {
        None
    };
    Ok(api::SessionConfig {
        server_url: required(args, "--server")?,
        ca_bundle: hex::decode(ca.trim()).map_err(|_| "--ca is not hex")?,
        key_store: api::KeyStoreConfig {
            kind: api::KeyStoreKind::OsDefault,
            uri: None,
        },
        data_dir: Some(required(args, "--data")?),
        relay_policy,
        identity_change_policy: None,
        revocation_grace_ms: None,
        external_transport: None,
    })
}

fn credentials(args: &[String]) -> Result<api::Credentials, String> {
    let password = std::env::var("QALQON_PASSWORD").map_err(|_| "QALQON_PASSWORD is not set")?;
    Ok(api::Credentials {
        user_id: required(args, "--user")?,
        secret: password.into_bytes(),
        mfa_code: None,
    })
}

fn say(value: serde_json::Value) {
    println!("{value}");
}

fn wait_for_channel_request(
    session: &qalqon_sdk::Session,
    timeout: Duration,
) -> Result<(String, api::PeerIdentity), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match session.next_event(200).map_err(|e| e.to_string())? {
            Some(api::Event::ChannelRequested {
                request_id, peer, ..
            }) => return Ok((request_id, peer)),
            Some(event) => say(json!({ "event": event })),
            None => {}
        }
    }
    Err("no call arrived in time".into())
}

fn run_call(args: &[String]) -> Result<(), String> {
    let session =
        qalqon_sdk::connect(config(args)?, credentials(args)?).map_err(|e| e.to_string())?;
    say(json!({ "state": "connected" }));
    let records: u32 = value(args, "--records")
        .map_or(Ok(1000), |v| v.parse())
        .map_err(|_| "--records is not a number")?;
    let peer = api::PeerRef {
        user_id: required(args, "--peer")?,
        device_id: None,
    };
    let options = api::ChannelOptions {
        label: "interop".into(),
        ordered: true,
        reliable: true,
        timeout_ms: None,
    };
    let channel = session
        .open_channel(peer.clone(), options)
        .map_err(|e| e.to_string())?;
    let info = channel.info().map_err(|e| e.to_string())?;
    say(json!({ "channel": info }));

    // Send and read back, with a bounded number outstanding.
    let mut sent = 0u32;
    let mut received = 0u32;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut rekeyed = false;
    while received < records {
        if Instant::now() > deadline {
            return Err(format!("only {received} of {records} came back"));
        }
        while sent < records && sent - received < 64 {
            channel
                .send(format!("record {sent:06} {}", "x".repeat(64)).as_bytes())
                .map_err(|e| e.to_string())?;
            sent += 1;
        }
        if let Some(message) = channel.receive(50).map_err(|e| e.to_string())? {
            let text = String::from_utf8(message).map_err(|_| "a reply is not text")?;
            let expected = format!("record {received:06} {}", "x".repeat(64));
            if text != expected {
                return Err(format!("reply {received} is wrong: {text}"));
            }
            received += 1;
        }
        if !rekeyed && received >= records / 2 {
            session
                .rotate_keys(Some(peer.clone()))
                .map_err(|e| e.to_string())?;
            rekeyed = true;
            say(json!({ "rekeyed_at": received }));
        }
    }
    let info = channel.info().map_err(|e| e.to_string())?;
    let export = session
        .export_audit(api::AuditExportRequest {
            from_ms: None,
            to_ms: None,
        })
        .map_err(|e| e.to_string())?;
    let entries = String::from_utf8_lossy(&export.events).lines().count();
    session.close().map_err(|e| e.to_string())?;
    say(json!({
        "result": "ok",
        "records": received,
        "path": info.path,
        "key_epoch": info.key_epoch,
        "peer_status": info.peer.status,
        "safety_number": info.peer.safety_number,
        "audit_entries": entries,
        "provider": qalqon_sdk::provider_name(),
    }));
    Ok(())
}

fn run_answer(args: &[String]) -> Result<(), String> {
    let session =
        qalqon_sdk::connect(config(args)?, credentials(args)?).map_err(|e| e.to_string())?;
    say(json!({ "state": "connected" }));
    let wait: u64 = value(args, "--wait-ms")
        .map_or(Ok(60_000), |v| v.parse())
        .map_err(|_| "--wait-ms is not a number")?;
    let (request_id, caller) = wait_for_channel_request(&session, Duration::from_millis(wait))?;
    say(json!({ "call_from": caller }));
    let channel = session
        .accept_channel(&request_id)
        .map_err(|e| e.to_string())?;
    let info = channel.info().map_err(|e| e.to_string())?;
    say(json!({ "channel": info }));
    let mut echoed = 0u64;
    let reason = loop {
        match channel.receive(200) {
            Ok(Some(message)) => {
                channel.send(&message).map_err(|e| e.to_string())?;
                echoed += 1;
            }
            Ok(None) => {}
            Err(e) => break e.to_string(),
        }
    };
    let info_status = info.peer.status;
    say(json!({
        "result": "ok",
        "records": echoed,
        "ended": reason,
        "path": info.path,
        "peer_status": info_status,
        "safety_number": info.peer.safety_number,
        "provider": qalqon_sdk::provider_name(),
    }));
    let _ = session.close();
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("enroll") => {
            let request = api::EnrollmentRequest {
                enrollment_token: required(&args, "--token")?,
                device_name: value(&args, "--name").unwrap_or_else(|| "cli-rust".into()),
            };
            let result =
                qalqon_sdk::enroll_device(config(&args)?, request).map_err(|e| e.to_string())?;
            say(json!({ "enrolled": result }));
            Ok(())
        }
        Some("call") => run_call(&args),
        Some("answer") => run_answer(&args),
        _ => Err("usage: qalqon-cli-rust <enroll|call|answer> ...".into()),
    }
}

fn main() {
    if let Err(e) = run() {
        println!("{}", json!({ "result": "error", "error": e }));
        std::process::exit(1);
    }
}
