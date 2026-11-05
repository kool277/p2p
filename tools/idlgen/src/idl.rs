//! The IDL's model, parsed and checked. Order is kept as written, because generated
//! files and error tables should read in the same order as the source.

use serde_yaml::{Mapping, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Bool,
    U16,
    U32,
    U64,
    Str,
    Bytes,
    Named(String),
    Optional(Box<Ty>),
    List(Box<Ty>),
}

impl Ty {
    pub fn parse(text: &str) -> Ty {
        if let Some(inner) = text.strip_suffix('?') {
            return Ty::Optional(Box::new(Ty::parse(inner)));
        }
        if let Some(inner) = text.strip_prefix("list<").and_then(|t| t.strip_suffix('>')) {
            return Ty::List(Box::new(Ty::parse(inner)));
        }
        match text {
            "bool" => Ty::Bool,
            "u16" => Ty::U16,
            "u32" => Ty::U32,
            "u64" => Ty::U64,
            "string" => Ty::Str,
            "bytes" => Ty::Bytes,
            other => Ty::Named(other.to_string()),
        }
    }

    pub fn source(&self) -> String {
        match self {
            Ty::Bool => "bool".into(),
            Ty::U16 => "u16".into(),
            Ty::U32 => "u32".into(),
            Ty::U64 => "u64".into(),
            Ty::Str => "string".into(),
            Ty::Bytes => "bytes".into(),
            Ty::Named(n) => n.clone(),
            Ty::Optional(t) => format!("{}?", t.source()),
            Ty::List(t) => format!("list<{}>", t.source()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: Ty,
    pub doc: String,
}

#[derive(Clone, Debug)]
pub struct ErrorDef {
    pub name: String,
    pub code: u32,
    pub doc: String,
}

#[derive(Clone, Debug)]
pub struct EnumDef {
    pub name: String,
    pub doc: String,
    pub values: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct RecordDef {
    pub name: String,
    pub doc: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct CaseDef {
    pub name: String,
    pub doc: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct VariantDef {
    pub name: String,
    pub doc: String,
    pub cases: Vec<CaseDef>,
}

#[derive(Clone, Debug)]
pub struct Callable {
    pub name: String,
    pub is_async: bool,
    pub doc: String,
    pub params: Vec<Field>,
    pub returns: Option<Ty>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct InterfaceDef {
    pub name: String,
    pub doc: String,
    pub methods: Vec<Callable>,
}

#[derive(Clone, Debug)]
pub struct Idl {
    pub api_version: String,
    pub protocol_version: String,
    pub errors: Vec<ErrorDef>,
    pub enums: Vec<EnumDef>,
    pub records: Vec<RecordDef>,
    pub variants: Vec<VariantDef>,
    pub functions: Vec<Callable>,
    pub interfaces: Vec<InterfaceDef>,
}

fn text(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn map<'a>(v: &'a Value, key: &str) -> Option<&'a Mapping> {
    v.get(key).and_then(Value::as_mapping)
}

fn name_of(k: &Value) -> String {
    k.as_str().expect("IDL keys are strings").to_string()
}

fn fields(v: &Value, key: &str) -> Vec<Field> {
    let Some(m) = map(v, key) else { return Vec::new() };
    m.iter()
        .map(|(k, f)| Field { name: name_of(k), ty: Ty::parse(&text(f, "type")), doc: text(f, "doc") })
        .collect()
}

fn callable(name: String, v: &Value) -> Callable {
    Callable {
        name,
        is_async: v.get("async").and_then(Value::as_bool).expect("async is required"),
        doc: text(v, "doc"),
        params: fields(v, "params"),
        returns: v.get("returns").and_then(Value::as_str).map(Ty::parse),
        errors: v
            .get("errors")
            .and_then(Value::as_sequence)
            .map(|s| s.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default(),
    }
}

impl Idl {
    pub fn parse(source: &str) -> Result<Idl, String> {
        let root: Value = serde_yaml::from_str(source).map_err(|e| format!("the IDL is not valid YAML: {e}"))?;
        let section = |key: &str| map(&root, key).ok_or_else(|| format!("the IDL has no {key} section"));
        let idl = Idl {
            api_version: text(&root, "api_version"),
            protocol_version: text(&root, "protocol_version"),
            errors: section("errors")?
                .iter()
                .map(|(k, v)| ErrorDef {
                    name: name_of(k),
                    code: v.get("code").and_then(Value::as_u64).expect("code is required") as u32,
                    doc: text(v, "doc"),
                })
                .collect(),
            enums: section("enums")?
                .iter()
                .map(|(k, v)| EnumDef {
                    name: name_of(k),
                    doc: text(v, "doc"),
                    values: map(v, "values")
                        .expect("an enum has values")
                        .iter()
                        .map(|(a, b)| (name_of(a), b.as_str().unwrap_or("").to_string()))
                        .collect(),
                })
                .collect(),
            records: section("records")?
                .iter()
                .map(|(k, v)| RecordDef { name: name_of(k), doc: text(v, "doc"), fields: fields(v, "fields") })
                .collect(),
            variants: section("variants")?
                .iter()
                .map(|(k, v)| VariantDef {
                    name: name_of(k),
                    doc: text(v, "doc"),
                    cases: map(v, "cases")
                        .expect("a variant has cases")
                        .iter()
                        .map(|(a, c)| CaseDef { name: name_of(a), doc: text(c, "doc"), fields: fields(c, "fields") })
                        .collect(),
                })
                .collect(),
            functions: section("functions")?.iter().map(|(k, v)| callable(name_of(k), v)).collect(),
            interfaces: section("interfaces")?
                .iter()
                .map(|(k, v)| InterfaceDef {
                    name: name_of(k),
                    doc: text(v, "doc"),
                    methods: map(v, "methods")
                        .expect("an interface has methods")
                        .iter()
                        .map(|(a, m)| callable(name_of(a), m))
                        .collect(),
                })
                .collect(),
        };
        idl.validate()?;
        Ok(idl)
    }

    pub fn is_interface(&self, name: &str) -> bool {
        self.interfaces.iter().any(|i| i.name == name)
    }

    pub fn is_enum(&self, name: &str) -> bool {
        self.enums.iter().any(|e| e.name == name)
    }

    pub fn is_record(&self, name: &str) -> bool {
        self.records.iter().any(|e| e.name == name)
    }

    fn known(&self, name: &str) -> bool {
        self.is_interface(name)
            || self.is_enum(name)
            || self.is_record(name)
            || self.variants.iter().any(|v| v.name == name)
    }

    fn check_ty(&self, ty: &Ty, at: &str, problems: &mut Vec<String>) {
        match ty {
            Ty::Named(n) if !self.known(n) => problems.push(format!("{at}: unknown type {n}")),
            Ty::Optional(t) | Ty::List(t) => self.check_ty(t, at, problems),
            _ => {}
        }
    }

    fn check_callable(&self, c: &Callable, at: &str, problems: &mut Vec<String>) {
        if c.doc.is_empty() {
            problems.push(format!("{at}: no doc"));
        }
        for p in &c.params {
            self.check_ty(&p.ty, &format!("{at}.{}", p.name), problems);
            if p.doc.is_empty() {
                problems.push(format!("{at}.{}: no doc", p.name));
            }
        }
        if let Some(r) = &c.returns {
            self.check_ty(r, &format!("{at} returns"), problems);
        }
        for e in &c.errors {
            if e == "ok" {
                problems.push(format!("{at}: ok is not an error"));
            }
            if !self.errors.iter().any(|d| d.name == *e) {
                problems.push(format!("{at}: unknown error {e}"));
            }
        }
    }

    fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        let mut codes = std::collections::HashSet::new();
        for e in &self.errors {
            if !codes.insert(e.code) {
                problems.push(format!("error code {} is used twice", e.code));
            }
        }
        for r in &self.records {
            for f in &r.fields {
                self.check_ty(&f.ty, &format!("{}.{}", r.name, f.name), &mut problems);
            }
        }
        for v in &self.variants {
            for c in &v.cases {
                for f in &c.fields {
                    self.check_ty(&f.ty, &format!("{}.{}.{}", v.name, c.name, f.name), &mut problems);
                }
            }
        }
        for f in &self.functions {
            self.check_callable(f, &f.name, &mut problems);
        }
        for i in &self.interfaces {
            for m in &i.methods {
                self.check_callable(m, &format!("{}.{}", i.name, m.name), &mut problems);
            }
        }
        if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
    }
}

pub fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn upper_camel(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

pub fn lower_camel(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}
