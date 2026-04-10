// IPC layer — one thin wrapper per Tauri command defined in
// app/src-tauri/src/commands.rs. Every call goes through here so
// there's a single place to audit the boundary shape and a single
// place to catch errors.
//
// Types mirror the Rust side by name. If you add a field to
// ItemMetadata in unovault-core::ipc, mirror it here — the build
// will not catch a drift because TypeScript has no cross-language
// schema check yet. A future sprint will emit the types from
// ts-rs or similar.

import { invoke } from '@tauri-apps/api/core';

// =============================================================================
// TYPES — mirror unovault_core::ipc
// =============================================================================

export type ItemKindTag =
  | 'Password'
  | 'Passkey'
  | 'Totp'
  | 'SshKey'
  | 'ApiToken'
  | 'SecureNote';

export interface ItemMetadata {
  id: string;
  title: string;
  kind: ItemKindTag;
  username: string | null;
  url: string | null;
  has_password: boolean;
  has_totp: boolean;
  has_passkey: boolean;
  created_at_ms: number;
  modified_at_ms: number;
}

export type CommandErrorCategory =
  | 'UserActionable'
  | 'NetworkTransient'
  | 'HardwareIssue'
  | 'BugInUnovault'
  | 'PlatformPolicy';

export interface CommandErrorShape {
  category: CommandErrorCategory;
  message: string;
}

// Narrows an unknown Tauri IPC error into the CommandErrorShape.
// Tauri invoke() rejects with the deserialized CommandError JSON
// value — our backend is `#[serde(tag = "category", content = "message")]`
// so the shape is { category, message }.
export function toCommandError(raw: unknown): CommandErrorShape {
  if (
    raw &&
    typeof raw === 'object' &&
    'category' in raw &&
    'message' in raw &&
    typeof (raw as any).category === 'string' &&
    typeof (raw as any).message === 'string'
  ) {
    return raw as CommandErrorShape;
  }
  return {
    category: 'BugInUnovault',
    message: `unrecognised error shape: ${JSON.stringify(raw)}`,
  };
}

// =============================================================================
// COMMAND WRAPPERS
// =============================================================================

export async function createVault(
  bundlePath: string,
  password: string,
): Promise<ItemMetadata[]> {
  return invoke('create_vault', { bundlePath, password });
}

export async function unlockVault(
  bundlePath: string,
  password: string,
): Promise<ItemMetadata[]> {
  return invoke('unlock_vault', { bundlePath, password });
}

export async function lockVault(): Promise<void> {
  return invoke('lock_vault');
}

export async function isUnlocked(): Promise<boolean> {
  return invoke('is_unlocked');
}

export async function listItems(): Promise<ItemMetadata[]> {
  return invoke('list_items');
}

export async function getItem(itemId: string): Promise<ItemMetadata | null> {
  return invoke('get_item', { itemId });
}

export async function addItem(
  title: string,
  kind: ItemKindTag,
  username: string | null,
  url: string | null,
): Promise<ItemMetadata> {
  return invoke('add_item', { title, kind, username, url });
}

export async function setPassword(
  itemId: string,
  password: string,
): Promise<ItemMetadata> {
  return invoke('set_password', { itemId, password });
}

export async function copyPasswordToClipboard(itemId: string): Promise<void> {
  return invoke('copy_password_to_clipboard', { itemId });
}

export async function formatVersion(): Promise<number> {
  return invoke('format_version');
}
