//! `qalqond`: the SDK API over a local socket, for languages that cannot load a library
//! (ADR-0004). It embeds the core, so keys never leave this process. Any process running
//! as the same user can reach it: this protects against other users and remote hosts, not
//! against malware running as that user.
//!
//! ```text
//! qalqond serve --socket <path>            a Unix socket, directory mode 0700, checked with SO_PEERCRED on Linux
//! qalqond serve --tcp 127.0.0.1:0 --token-file <path>   loopback TCP with a per-launch token
//! qalqond client <socket>                  JSON lines on stdin and stdout, for shell scripts
//! qalqond call <socket> <method> <json>    one call. Handles die with the connection
//! ```
#![forbid(unsafe_code)]

#[rustfmt::skip]
mod generated;

use qalqon_sdk::api;
use qalqon_sdk::{ApiError, ErrorKind};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// A longer or malformed frame closes the connection.
const MAX_FRAME: usize = 16 * 1024 * 1024;
const ABI_MAJOR: u64 = 0;

fn arg<T: DeserializeOwned>(params: &Value, name: &str) -> Result<T, ApiError> {
    serde_json::from_value(params.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|_| ErrorKind::InvalidArgument.into())
}

fn text_arg(params: &Value, name: &str) -> Result<String, ApiError> {
    arg(params, name)
}

fn bytes_arg(params: &Value, name: &str) -> Result<Vec<u8>, ApiError> {
    let text: String = arg(params, name)?;
    api::b64::decode(&text).ok_or_else(|| ErrorKind::InvalidArgument.into())
}

fn optional_bytes_arg(params: &Value, name: &str) -> Result<Option<Vec<u8>>, ApiError> {
    let text: Option<String> = arg(params, name)?;
    text.map(|t| api::b64::decode(&t).ok_or_else(|| ErrorKind::InvalidArgument.into()))
        .transpose()
}

fn to_value<T: serde::Serialize>(value: T) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|_| ErrorKind::Internal.into())
}

/// The objects one connection has created. Closing the connection closes them.
#[derive(Default)]
pub(crate) struct Handles {
    next: u64,
    sessions: HashMap<String, qalqon_sdk::Session>,
    channels: HashMap<String, qalqon_sdk::Channel>,
    transports: HashMap<String, qalqon_sdk::ExternalTransport>,
    servers: HashMap<String, qalqon_sdk::ServerCore>,
}

fn handle_of(params: &Value) -> Result<String, ApiError> {
    arg(params, "handle")
}

impl Handles {
    fn new_name(&mut self, kind: &str) -> String {
        self.next += 1;
        format!("{kind}-{}", self.next)
    }

    fn add_session(&mut self, object: qalqon_sdk::Session) -> Value {
        let name = self.new_name("session");
        self.sessions.insert(name.clone(), object);
        Value::String(name)
    }

    fn add_channel(&mut self, object: qalqon_sdk::Channel) -> Value {
        let name = self.new_name("channel");
        self.channels.insert(name.clone(), object);
        Value::String(name)
    }

    fn add_external_transport(&mut self, object: qalqon_sdk::ExternalTransport) -> Value {
        let name = self.new_name("transport");
        self.transports.insert(name.clone(), object);
        Value::String(name)
    }

    fn add_server_core(&mut self, object: qalqon_sdk::ServerCore) -> Value {
        let name = self.new_name("server");
        self.servers.insert(name.clone(), object);
        Value::String(name)
    }

    fn session(&self, params: &Value) -> Result<qalqon_sdk::Session, ApiError> {
        self.sessions
            .get(&handle_of(params)?)
            .cloned()
            .ok_or_else(|| ErrorKind::InvalidArgument.into())
    }

    fn channel(&self, params: &Value) -> Result<qalqon_sdk::Channel, ApiError> {
        self.channels
            .get(&handle_of(params)?)
            .cloned()
            .ok_or_else(|| ErrorKind::InvalidArgument.into())
    }

    fn external_transport(
        &self,
        params: &Value,
    ) -> Result<qalqon_sdk::ExternalTransport, ApiError> {
        self.transports
            .get(&handle_of(params)?)
            .cloned()
            .ok_or_else(|| ErrorKind::InvalidArgument.into())
    }

    fn server_core(&self, params: &Value) -> Result<qalqon_sdk::ServerCore, ApiError> {
        self.servers
            .get(&handle_of(params)?)
            .cloned()
            .ok_or_else(|| ErrorKind::InvalidArgument.into())
    }
}

impl Drop for Handles {
    fn drop(&mut self) {
        for session in self.sessions.values() {
            let _ = session.close();
        }
    }
}

fn read_frame(stream: &mut impl Read) -> io::Result<Option<Value>> {
    let mut header = [0u8; 4];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a frame is too long",
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a frame is not JSON"))
}

fn write_frame(stream: &mut impl Write, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    let length = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "too long"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn error_reply(id: &Value, code: u32, name: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": name, "data": { "name": name } } })
}

/// `qalqond.hello`, which must come first. Anything else closes the connection.
fn check_hello(request: &Value, token: Option<&[u8]>) -> Result<Value, Value> {
    let id = &request["id"];
    let refuse = |kind: ErrorKind| error_reply(id, kind.code(), kind.name());
    if request["method"] != "qalqond.hello" {
        return Err(refuse(ErrorKind::InvalidState));
    }
    if request["params"]["abi"].as_u64() != Some(ABI_MAJOR) {
        return Err(refuse(ErrorKind::Unsupported));
    }
    if let Some(expected) = token {
        let presented = request["params"]["token"].as_str().unwrap_or("");
        if !qalqon_sdk::constant_time_eq(presented.as_bytes(), expected) {
            return Err(refuse(ErrorKind::AccessDenied));
        }
    }
    Ok(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "abi": ABI_MAJOR,
            "protocol_version": api::PROTOCOL_VERSION,
            "build_id": env!("CARGO_PKG_VERSION"),
            "provider": qalqon_sdk::provider_name(),
        },
    }))
}

fn serve_connection(mut stream: impl Read + Write, token: Option<&[u8]>) -> io::Result<()> {
    let Some(first) = read_frame(&mut stream)? else {
        return Ok(());
    };
    match check_hello(&first, token) {
        Ok(reply) => write_frame(&mut stream, &reply)?,
        Err(reply) => {
            let _ = write_frame(&mut stream, &reply);
            return Ok(());
        }
    }
    let mut handles = Handles::default();
    while let Some(request) = read_frame(&mut stream)? {
        let id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or("").to_string();
        let empty = json!({});
        let params = request.get("params").unwrap_or(&empty);
        let reply = match generated::dispatch(&mut handles, &method, params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(e) => error_reply(&id, e.0.code(), e.0.name()),
        };
        write_frame(&mut stream, &reply)?;
    }
    Ok(())
}

/// The check in ADR-0004: the peer's UID must match the daemon's. On other Unix systems,
/// the socket's `0700` directory gives the same guarantee, and `getpeereid` is a recorded gap.
#[cfg(target_os = "linux")]
fn peer_is_same_user(stream: &UnixStream) -> bool {
    use rustix::net::sockopt::socket_peercred;
    socket_peercred(stream).is_ok_and(|credentials| credentials.uid == rustix::process::getuid())
}

#[cfg(not(target_os = "linux"))]
fn peer_is_same_user(_: &UnixStream) -> bool {
    true
}

fn serve_unix(path: &Path) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "the socket needs a directory")
    })?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir)?;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} must not be accessible by other users", dir.display()),
        ));
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    eprintln!(
        "qalqond listening on {} (provider: {})",
        path.display(),
        qalqon_sdk::provider_name()
    );
    for stream in listener.incoming().flatten() {
        if !peer_is_same_user(&stream) {
            continue;
        }
        std::thread::spawn(move || {
            let _ = serve_connection(stream, None);
        });
    }
    Ok(())
}

fn serve_tcp(address: &str, token_file: &Path) -> io::Result<()> {
    let provider = qalqon_sdk::provider();
    let mut random = [0u8; 32];
    provider
        .random(&mut random)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let token = crypto_provider::to_hex(&random);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(token_file)?;
    file.write_all(token.as_bytes())?;
    drop(file);
    let listener = TcpListener::bind(address)?;
    let bound = listener.local_addr()?;
    if !bound.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "qalqond only listens on loopback",
        ));
    }
    eprintln!(
        "qalqond listening on {bound} with its token in {}",
        token_file.display()
    );
    let token = std::sync::Arc::new(token.into_bytes());
    for stream in listener.incoming().flatten() {
        let token = token.clone();
        std::thread::spawn(move || {
            let _ = serve_connection(stream, Some(&token));
        });
    }
    Ok(())
}

enum Endpoint {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Endpoint {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Endpoint::Unix(s) => s.read(buf),
            Endpoint::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Endpoint {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Endpoint::Unix(s) => s.write(buf),
            Endpoint::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Endpoint::Unix(s) => s.flush(),
            Endpoint::Tcp(s) => s.flush(),
        }
    }
}

fn connect_endpoint(endpoint: &str) -> io::Result<Endpoint> {
    if endpoint.contains('/') {
        Ok(Endpoint::Unix(UnixStream::connect(endpoint)?))
    } else {
        Ok(Endpoint::Tcp(TcpStream::connect(endpoint)?))
    }
}

fn say_hello(stream: &mut Endpoint, client: &str) -> io::Result<()> {
    let hello = json!({ "jsonrpc": "2.0", "id": 0, "method": "qalqond.hello", "params": { "abi": ABI_MAJOR, "client": client } });
    write_frame(stream, &hello)?;
    let reply = read_frame(stream)?.ok_or(io::ErrorKind::UnexpectedEof)?;
    if reply.get("error").is_some() {
        return Err(io::Error::other(format!(
            "qalqond refused the connection: {reply}"
        )));
    }
    Ok(())
}

/// JSON lines on stdin and stdout, for a shell co-process. One connection, so handles
/// stay alive between calls.
fn run_client(endpoint: &str) -> io::Result<()> {
    let mut stream = connect_endpoint(endpoint)?;
    say_hello(&mut stream, "shell/0.1.0")?;
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a line is not JSON"))?;
        write_frame(&mut stream, &request)?;
        let reply = read_frame(&mut stream)?.ok_or(io::ErrorKind::UnexpectedEof)?;
        writeln!(stdout, "{reply}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn run_call(endpoint: &str, method: &str, params: &str) -> io::Result<i32> {
    let mut stream = connect_endpoint(endpoint)?;
    say_hello(&mut stream, "call/0.1.0")?;
    let params: Value = serde_json::from_str(params)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the parameters are not JSON"))?;
    write_frame(
        &mut stream,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
    )?;
    let reply = read_frame(&mut stream)?.ok_or(io::ErrorKind::UnexpectedEof)?;
    if let Some(error) = reply.get("error") {
        eprintln!("{error}");
        return Ok(1);
    }
    println!("{}", reply["result"]);
    Ok(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let outcome = match args.first().map(String::as_str) {
        Some("serve") => match (value("--socket"), value("--tcp"), value("--token-file")) {
            (Some(socket), _, _) => serve_unix(&PathBuf::from(socket)).map(|()| 0),
            (None, Some(address), Some(token)) => {
                serve_tcp(&address, &PathBuf::from(token)).map(|()| 0)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serve needs --socket, or --tcp with --token-file",
            )),
        },
        Some("client") => match args.get(1) {
            Some(endpoint) => run_client(endpoint).map(|()| 0),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client needs a socket",
            )),
        },
        Some("call") => match (args.get(1), args.get(2), args.get(3)) {
            (Some(endpoint), Some(method), params) => {
                run_call(endpoint, method, params.map_or("{}", String::as_str))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "call needs a socket and a method",
            )),
        },
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: qalqond <serve|client|call> ...",
        )),
    };
    match outcome {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("qalqond: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dispatch_table_matches_the_json_rpc_schema() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../idl/generated/qalqon.jsonrpc.json"
        ))
        .unwrap();
        let schema: Value = serde_json::from_str(&text).unwrap();
        let in_schema: Vec<&str> = schema["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap())
            .collect();
        assert_eq!(in_schema, generated::METHODS);
    }

    #[test]
    fn hello_must_come_first_and_be_the_right_version() {
        let good = json!({ "id": 1, "method": "qalqond.hello", "params": { "abi": 0 } });
        assert!(check_hello(&good, None).is_ok());
        let wrong = json!({ "id": 1, "method": "connect", "params": {} });
        assert!(check_hello(&wrong, None).is_err());
        let abi = json!({ "id": 1, "method": "qalqond.hello", "params": { "abi": 9 } });
        assert_eq!(
            check_hello(&abi, None).unwrap_err()["error"]["code"],
            ErrorKind::Unsupported.code()
        );
    }

    #[test]
    fn a_wrong_token_is_refused() {
        let hello = |token: &str| json!({ "id": 1, "method": "qalqond.hello", "params": { "abi": 0, "token": token } });
        assert!(check_hello(&hello("secret"), Some(b"secret")).is_ok());
        assert_eq!(
            check_hello(&hello("guess"), Some(b"secret")).unwrap_err()["error"]["code"],
            ErrorKind::AccessDenied.code()
        );
        assert!(
            check_hello(
                &json!({ "id": 1, "method": "qalqond.hello", "params": { "abi": 0 } }),
                Some(b"secret")
            )
            .is_err()
        );
    }

    #[test]
    fn frames_round_trip_and_oversized_frames_are_refused() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &json!({ "a": 1 })).unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap().unwrap()["a"], 1);
        let oversized = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert!(read_frame(&mut oversized.as_slice()).is_err());
        assert!(read_frame(&mut [].as_slice()).unwrap().is_none());
    }
}
