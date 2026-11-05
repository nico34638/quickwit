// Copyright 2021-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Authorization token of the UI, sent in the `Authorization` header of the API calls when
// authorization is enabled on the cluster.

const AUTH_STORAGE_KEY = "quickwitAuth";

export type StoredAuth = {
  // Quickwit token (biscuit).
  token: string;
  // Known when the token was obtained through the JWT exchange.
  user?: string;
  roles?: string[];
  // RFC 3339.
  expiresAt?: string;
};

// Identity and rights of the token, returned by `GET /api/v1/auth/whoami`.
export type Identity = {
  // When false, no token is required and every operation is allowed.
  authorization_enabled: boolean;
  user: string | null;
  roles: string[];
  // Node tokens are granted every right.
  node: boolean;
  grants: { rights: string[]; indexes: string[] }[];
  // The `cluster` right: cluster state, node config, developer API.
  cluster: boolean;
};

// The REST API returns errors as `{"message": "..."}`: returns the message, or the raw text.
export function parseErrorMessage(text: string): string {
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed?.message === "string") {
      return parsed.message;
    }
  } catch {
    // Not JSON.
  }
  return text;
}

const authEvents = new EventTarget();
const AUTH_CHANGED_EVENT = "auth-changed";
const AUTH_REQUIRED_EVENT = "auth-required";

function isExpired(auth: StoredAuth): boolean {
  if (auth.expiresAt === undefined) {
    return false;
  }
  const expiresAtMillis = Date.parse(auth.expiresAt);
  return !Number.isNaN(expiresAtMillis) && expiresAtMillis <= Date.now();
}

// Returns the stored token, unless it expired.
export function getStoredAuth(): StoredAuth | null {
  let storedValue: string | null;
  try {
    storedValue = localStorage.getItem(AUTH_STORAGE_KEY);
  } catch {
    return null;
  }
  if (storedValue === null) {
    return null;
  }
  try {
    const auth = JSON.parse(storedValue) as StoredAuth;
    if (
      typeof auth.token !== "string" ||
      auth.token === "" ||
      isExpired(auth)
    ) {
      return null;
    }
    return auth;
  } catch {
    return null;
  }
}

export function storeAuth(auth: StoredAuth): void {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
  authEvents.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
}

export function clearStoredAuth(): void {
  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Nothing to clear.
  }
  authEvents.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
}

// Returns the `Authorization` header to add to API calls, if a token is stored.
export function authorizationHeaders(): Record<string, string> {
  const auth = getStoredAuth();
  if (auth === null) {
    return {};
  }
  return { Authorization: `Bearer ${auth.token}` };
}

// Called by the API client when the server rejects a call as unauthenticated (401).
export function notifyAuthRequired(): void {
  authEvents.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
}

function subscribe(eventName: string, listener: () => void): () => void {
  authEvents.addEventListener(eventName, listener);
  return () => authEvents.removeEventListener(eventName, listener);
}

export function onAuthRequired(listener: () => void): () => void {
  return subscribe(AUTH_REQUIRED_EVENT, listener);
}

export function onAuthChanged(listener: () => void): () => void {
  return subscribe(AUTH_CHANGED_EVENT, listener);
}

// JWTs are made of three base64url parts separated by dots, whereas Quickwit tokens are a single
// base64url string.
export function isJwt(value: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value);
}

// Exchanges a JWT issued by the identity provider for a Quickwit token.
export async function exchangeJwt(
  jwt: string,
  host: string = window.location.origin,
): Promise<StoredAuth> {
  const response = await fetch(`${host}/api/v1/auth/token`, {
    method: "POST",
    headers: { Accept: "application/json", Authorization: `Bearer ${jwt}` },
  });
  if (!response.ok) {
    const message = parseErrorMessage(await response.text());
    return Promise.reject({ message, status: response.status });
  }
  const body = (await response.json()) as {
    token: string;
    user: string;
    roles: string[];
    expires_at: string;
  };
  return {
    token: body.token,
    user: body.user,
    roles: body.roles,
    expiresAt: body.expires_at,
  };
}
