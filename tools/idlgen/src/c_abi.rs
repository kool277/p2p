//! The C ABI (ADR-0002, part 4): opaque handles, status codes, polled results. Structured
//! values cross as JSON text, the same encoding the sidecar uses, so a binding needs one
//! decoder rather than a struct layout for each record. Scalars and bytes stay native.

use crate::idl::*;
use std::fmt::Write;

fn is_optional_bytes(ty: &Ty) -> bool {
    matches!(ty, Ty::Optional(t) if **t == Ty::Bytes)
}

fn abi_params(p: &Field) -> Vec<String> {
    let name = snake(&p.name);
    match &p.ty {
        Ty::Bool => vec![format!("{name}: bool")],
        Ty::U16 => vec![format!("{name}: u16")],
        Ty::U32 => vec![format!("{name}: u32")],
        Ty::U64 => vec![format!("{name}: u64")],
        Ty::Bytes => vec![format!("{name}: *const u8"), format!("{name}_len: usize")],
        t if is_optional_bytes(t) => {
            vec![format!("{name}: *const u8"), format!("{name}_len: usize")]
        }
        _ => vec![format!("{name}: *const c_char")],
    }
}

/// The Rust type of a JSON argument, with `api::` on the IDL's own names.
pub fn api_ty(ty: &Ty) -> String {
    match ty {
        Ty::Bool => "bool".into(),
        Ty::U16 => "u16".into(),
        Ty::U32 => "u32".into(),
        Ty::U64 => "u64".into(),
        Ty::Str => "String".into(),
        Ty::Bytes => "Vec<u8>".into(),
        Ty::Named(n) => format!("api::{n}"),
        Ty::Optional(t) => format!("Option<{}>", api_ty(t)),
        Ty::List(t) => format!("Vec<{}>", api_ty(t)),
    }
}

fn decode_param(p: &Field) -> String {
    let name = snake(&p.name);
    match &p.ty {
        Ty::Bool | Ty::U16 | Ty::U32 | Ty::U64 => String::new(),
        Ty::Str => format!("        let {name} = unsafe {{ str_arg({name}) }}?;\n"),
        Ty::Bytes => format!("        let {name} = unsafe {{ bytes_arg({name}, {name}_len) }}?;\n"),
        t if is_optional_bytes(t) => {
            format!("        let {name} = unsafe {{ optional_bytes_arg({name}, {name}_len) }}?;\n")
        }
        t => format!(
            "        let {name}: {} = unsafe {{ json_arg({name}) }}?;\n",
            api_ty(t)
        ),
    }
}

fn out_params(returns: &Option<Ty>, idl: &Idl) -> Vec<String> {
    match returns {
        None => vec![],
        Some(Ty::Bool) => vec!["out: *mut bool".into()],
        Some(Ty::U16) => vec!["out: *mut u16".into()],
        Some(Ty::U32) => vec!["out: *mut u32".into()],
        Some(Ty::U64) => vec!["out: *mut u64".into()],
        Some(Ty::Named(n)) if idl.is_interface(n) => {
            vec![format!("out: *mut *mut qalqon_{}_t", snake(n))]
        }
        Some(Ty::Optional(_)) => vec![
            "out: *mut qalqon_buffer_t".into(),
            "out_present: *mut bool".into(),
        ],
        Some(_) => vec!["out: *mut qalqon_buffer_t".into()],
    }
}

fn write_result(returns: &Option<Ty>, idl: &Idl) -> String {
    match returns {
        None => "        Ok(())\n".into(),
        Some(Ty::Bool | Ty::U16 | Ty::U32 | Ty::U64) => {
            "        unsafe { write_out(out, result) }\n".into()
        }
        Some(Ty::Named(n)) if idl.is_interface(n) => {
            format!(
                "        unsafe {{ write_out(out, Box::into_raw(Box::new(qalqon_{}_t {{ inner: result }}))) }}\n",
                snake(n)
            )
        }
        Some(Ty::Str) => "        unsafe { write_buffer(out, result.into_bytes()) }\n".into(),
        Some(Ty::Bytes) => "        unsafe { write_buffer(out, result) }\n".into(),
        Some(Ty::Optional(t)) if **t == Ty::Bytes => {
            "        unsafe { write_optional_buffer(out, out_present, result) }\n".into()
        }
        Some(Ty::Optional(_)) => {
            "        unsafe { write_optional_json(out, out_present, result) }\n".into()
        }
        Some(_) => "        unsafe { write_json(out, &result) }\n".into(),
    }
}

fn write_function(out: &mut String, c: &Callable, interface: Option<&InterfaceDef>, idl: &Idl) {
    let name = match interface {
        Some(i) => format!("qalqon_{}_{}", snake(&i.name), snake(&c.name)),
        None => format!("qalqon_{}", snake(&c.name)),
    };
    let mut params: Vec<String> = Vec::new();
    if let Some(i) = interface {
        params.push(format!("handle: *const qalqon_{}_t", snake(&i.name)));
    }
    for p in &c.params {
        params.extend(abi_params(p));
    }
    params.extend(out_params(&c.returns, idl));

    let _ = writeln!(out, "/// {}", c.doc);
    out.push_str("///\n/// # Safety\n/// Pointers must be valid for the call, as `bindings/c/README.md` describes.\n");
    out.push_str("#[unsafe(no_mangle)]\n");
    let _ = writeln!(
        out,
        "pub unsafe extern \"C\" fn {name}({}) -> qalqon_status_t {{",
        params.join(", ")
    );
    out.push_str("    guard(|| {\n");
    if interface.is_some() {
        out.push_str("        let object = unsafe { handle_ref(handle) }?;\n");
    }
    for p in &c.params {
        out.push_str(&decode_param(p));
    }
    let args: Vec<String> = c.params.iter().map(|p| snake(&p.name)).collect();
    let binding = if c.returns.is_some() {
        "let result = "
    } else {
        ""
    };
    match interface {
        Some(_) => {
            let _ = writeln!(
                out,
                "        {binding}object.inner.{}({})?;",
                snake(&c.name),
                args.join(", ")
            );
        }
        None => {
            let _ = writeln!(
                out,
                "        {binding}qalqon_sdk::{}({})?;",
                snake(&c.name),
                args.join(", ")
            );
        }
    }
    out.push_str(&write_result(&c.returns, idl));
    out.push_str("    })\n}\n\n");
}

pub fn generate(idl: &Idl) -> String {
    let mut out = String::from(
        "// @generated by tools/idlgen from core/idl/qalqon.api.yaml. Do not edit.\n\nuse super::*;\n\n",
    );
    for e in &idl.errors {
        let _ = writeln!(
            out,
            "/// {}\npub const QALQON_{}: qalqon_status_t = {};",
            e.doc,
            snake(&e.name).to_uppercase(),
            e.code
        );
    }
    out.push('\n');
    for i in &idl.interfaces {
        let sdk = if i.name == "ServerCore" {
            "qalqon_sdk::ServerCore".to_string()
        } else {
            format!("qalqon_sdk::{}", i.name)
        };
        let c = snake(&i.name);
        let _ = writeln!(
            out,
            "/// {}\npub struct qalqon_{c}_t {{\n    pub(crate) inner: {sdk},\n}}\n",
            i.doc
        );
        let _ = writeln!(
            out,
            "/// Releases a handle. Passing null does nothing.\n///\n/// # Safety\n/// `handle` must have come from this library and must not be used afterwards.\n#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn qalqon_{c}_free(handle: *mut qalqon_{c}_t) {{\n    if !handle.is_null() {{\n        drop(unsafe {{ Box::from_raw(handle) }});\n    }}\n}}\n"
        );
    }
    for f in &idl.functions {
        write_function(&mut out, f, None, idl);
    }
    for i in &idl.interfaces {
        for m in &i.methods {
            write_function(&mut out, m, Some(i), idl);
        }
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    out
}

pub fn header(source_dir: &std::path::Path) -> String {
    let config = cbindgen::Config {
        language: cbindgen::Language::C,
        include_guard: Some("QALQON_H".into()),
        header: Some(
            "/* @generated by tools/idlgen from core/idl/qalqon.api.yaml through cbindgen. Do not edit.\n *\n * Every fallible call returns a qalqon_status_t, whose values are the IDL's error codes.\n * Structured values cross as JSON text, in the encoding docs/SDK-API.md describes.\n * Keys never cross this boundary as bytes. */".into(),
        ),
        documentation: true,
        cpp_compat: true,
        usize_is_size_t: true,
        no_includes: true,
        sys_includes: vec!["stdint.h".into(), "stddef.h".into(), "stdbool.h".into()],
        ..cbindgen::Config::default()
    };
    let mut out = Vec::new();
    cbindgen::Builder::new()
        .with_config(config)
        .with_src(source_dir.join("lib.rs"))
        .with_src(source_dir.join("generated.rs"))
        .generate()
        .expect("cbindgen reads the ABI source")
        .write(&mut out);
    String::from_utf8(out).expect("the header is UTF-8")
}
