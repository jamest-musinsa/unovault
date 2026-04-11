//! JSON-RPC-ish protocol between the Chrome extension and the
//! native messaging host.
//!
//! Mirrors `extension/src/protocol.ts` field for field. Changes here
//! **must** be reflected on the TypeScript side; a future sprint
//! replaces this manual mirroring with code generation.

use serde::{Deserialize, Serialize};

/// Incoming request from the extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRequest {
    pub request_id: String,
    pub payload: HostRequestPayload,
}

/// Request payloads the host understands. The `method` tag is what
/// the TS side sends as the discriminator; matching serde's
/// `#[serde(tag = "method")]` keeps both sides in sync without a
/// shared schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum HostRequestPayload {
    /// Liveness probe. Host responds with its version.
    Ping,

    /// Ask the desktop app for every item matching the given
    /// page origin.
    ListMatchingItems { origin: String },

    /// Fetch the plaintext password for a specific item id.
    GetPassword { item_id: String },
}

/// Outgoing response to the extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostResponse {
    pub request_id: String,
    pub payload: HostResponsePayload,
}

/// Response payloads. The `kind` discriminator lines up with the
/// TypeScript union so the extension can pattern-match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostResponsePayload {
    Pong { version: String },
    ListMatchingItems { items: Vec<ItemRef> },
    GetPassword { password: String },
    Error { category: String, message: String },
}

/// Metadata for one vault item surfaced to the extension. Carries
/// no password bytes — those go through a dedicated `get_password`
/// request so the audit trail is one grep away.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemRef {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ping_round_trips() {
        let req = HostRequest {
            request_id: "r1".into(),
            payload: HostRequestPayload::Ping,
        };
        let json = serde_json::to_string(&req).expect("encode");
        // Check the wire shape — the TS side is producing JSON
        // matching this exact form.
        assert!(json.contains("\"method\":\"ping\""));
        let decoded: HostRequest = serde_json::from_str(&json).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_list_matching_items_uses_snake_case_method() {
        let json = r#"{"request_id":"r2","payload":{"method":"list_matching_items","origin":"https://github.com"}}"#;
        let decoded: HostRequest = serde_json::from_str(json).expect("decode");
        match decoded.payload {
            HostRequestPayload::ListMatchingItems { origin } => {
                assert_eq!(origin, "https://github.com");
            }
            other => panic!("expected ListMatchingItems, got {other:?}"),
        }
    }

    #[test]
    fn request_get_password_parses() {
        let json = r#"{"request_id":"r3","payload":{"method":"get_password","item_id":"abc-123"}}"#;
        let decoded: HostRequest = serde_json::from_str(json).expect("decode");
        match decoded.payload {
            HostRequestPayload::GetPassword { item_id } => {
                assert_eq!(item_id, "abc-123");
            }
            other => panic!("expected GetPassword, got {other:?}"),
        }
    }

    #[test]
    fn response_error_encodes_with_category_and_message() {
        let resp = HostResponse {
            request_id: "r4".into(),
            payload: HostResponsePayload::Error {
                category: "UserActionable".into(),
                message: "vault is locked".into(),
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        assert!(json.contains("\"kind\":\"error\""));
        assert!(json.contains("\"category\":\"UserActionable\""));
        assert!(json.contains("\"message\":\"vault is locked\""));
    }

    #[test]
    fn response_pong_carries_version() {
        let resp = HostResponse {
            request_id: "r5".into(),
            payload: HostResponsePayload::Pong {
                version: "0.0.1".into(),
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        assert!(json.contains("\"kind\":\"pong\""));
        assert!(json.contains("\"version\":\"0.0.1\""));
    }

    #[test]
    fn response_list_matching_items_round_trips() {
        let resp = HostResponse {
            request_id: "r6".into(),
            payload: HostResponsePayload::ListMatchingItems {
                items: vec![
                    ItemRef {
                        id: "item-a".into(),
                        title: "GitHub".into(),
                        username: Some("james".into()),
                    },
                    ItemRef {
                        id: "item-b".into(),
                        title: "Gmail".into(),
                        username: None,
                    },
                ],
            },
        };
        let json = serde_json::to_string(&resp).expect("encode");
        let decoded: HostResponse = serde_json::from_str(&json).expect("decode");
        assert_eq!(decoded, resp);
    }
}
