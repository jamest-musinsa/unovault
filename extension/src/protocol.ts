// Shared types for the native-messaging bridge between the extension
// and the unovault desktop app. Every frame is JSON, with a unique
// `request_id` that lets async responses arrive out-of-order.
//
// The request/response shapes MUST stay in lockstep with the Rust
// side — see `crates/unovault-native-host/src/protocol.rs`. A
// mismatch here surfaces as `{ error: "unknown method" }` from the
// host, which is fine during development but should become a hard
// compile-time check once we generate types from the Rust crate.

export type RequestId = string;

export interface PingRequest {
  method: 'ping';
}

export interface ListMatchingItemsRequest {
  method: 'list_matching_items';
  origin: string; // full origin like "https://github.com"
}

export interface GetPasswordRequest {
  method: 'get_password';
  item_id: string;
}

export type HostRequestPayload =
  | PingRequest
  | ListMatchingItemsRequest
  | GetPasswordRequest;

export interface HostRequest {
  request_id: RequestId;
  payload: HostRequestPayload;
}

// Metadata returned by list_matching_items. Titles and usernames are
// safe to expose to the extension; the actual password is fetched
// through a second request that the desktop app's AppState can gate
// on user presence (Touch ID, biometric prompt, etc.).
export interface ItemRef {
  id: string;
  title: string;
  username: string | null;
}

export interface PongResponse {
  kind: 'pong';
  version: string;
}

export interface ListMatchingItemsResponse {
  kind: 'list_matching_items';
  items: ItemRef[];
}

export interface GetPasswordResponse {
  kind: 'get_password';
  // The response carries the password plaintext over the native
  // messaging pipe. This is NOT the same as crossing the Tauri IPC
  // boundary — native messaging runs out-of-process and the only
  // consumer is the content script, which handles it in a single
  // paste call. We keep the exposure to one dedicated response type
  // so a future review can grep for every call site.
  password: string;
}

export interface ErrorResponse {
  kind: 'error';
  category: string;
  message: string;
}

export type HostResponsePayload =
  | PongResponse
  | ListMatchingItemsResponse
  | GetPasswordResponse
  | ErrorResponse;

export interface HostResponse {
  request_id: RequestId;
  payload: HostResponsePayload;
}

// Helper to generate a short random request ID. Not cryptographic —
// just enough to correlate async responses in a single session.
export function newRequestId(): RequestId {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
