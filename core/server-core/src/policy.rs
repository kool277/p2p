//! Policy evaluation: an access matrix over roles, operations and named resources
//! (build prompt §1.6). Deny overrides allow, and anything not allowed is denied.
//!
//! ```json
//! {
//!   "roles": { "user": ["login", "rendezvous"], "admin": ["*"] },
//!   "deny": [ { "subject": "mallory", "operation": "rendezvous", "object": "user:alice" } ]
//! }
//! ```
//! Confidentiality labels with flow control (class 1V and up) are not implemented.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Named operations a policy can allow.
pub mod operation {
    #![allow(missing_docs)]
    pub const LOGIN: &str = "login";
    pub const ENROLL: &str = "enroll";
    pub const RENDEZVOUS: &str = "rendezvous";
    pub const RENEW: &str = "renew";
}

/// A rule that removes access, which beats any role.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyRule {
    /// A user, or `*`.
    pub subject: String,
    /// An operation, or `*`.
    pub operation: String,
    /// A named resource such as `user:alice`, or `*`.
    pub object: String,
}

/// A parsed policy document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// What each role may do.
    #[serde(default)]
    pub roles: BTreeMap<String, Vec<String>>,
    /// Exceptions.
    #[serde(default)]
    pub deny: Vec<DenyRule>,
}

fn matches(pattern: &str, value: &str) -> bool {
    pattern == "*" || pattern == value
}

impl Policy {
    /// The default for a host that configures nothing: users may log in and call each
    /// other, and nothing else.
    pub fn default_document() -> serde_json::Value {
        serde_json::json!({
            "roles": {
                "user": ["login", "enroll", "rendezvous", "renew"],
                "admin": ["login", "enroll", "rendezvous", "renew"]
            },
            "deny": []
        })
    }

    /// Decides one access attempt.
    pub fn allows(&self, subject: &str, role: &str, operation: &str, object: &str) -> bool {
        if self.deny.iter().any(|r| {
            matches(&r.subject, subject)
                && matches(&r.operation, operation)
                && matches(&r.object, object)
        }) {
            return false;
        }
        self.roles
            .get(role)
            .is_some_and(|ops| ops.iter().any(|o| matches(o, operation)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_overrides_and_the_default_is_deny() {
        let policy: Policy = serde_json::from_value(serde_json::json!({
            "roles": { "user": ["login", "rendezvous"], "root": ["*"] },
            "deny": [ { "subject": "mallory", "operation": "rendezvous", "object": "user:alice" } ]
        }))
        .unwrap();
        assert!(policy.allows("bob", "user", "rendezvous", "user:alice"));
        assert!(!policy.allows("mallory", "user", "rendezvous", "user:alice"));
        assert!(policy.allows("mallory", "user", "rendezvous", "user:bob"));
        assert!(!policy.allows("bob", "user", "renew", "user:bob"));
        assert!(!policy.allows("bob", "nobody", "login", "x"));
        assert!(policy.allows("r", "root", "anything", "x"));
    }
}
