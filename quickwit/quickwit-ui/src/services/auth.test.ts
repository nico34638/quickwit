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

import { afterEach, describe, expect, it, jest } from "@jest/globals";
import {
  authorizationHeaders,
  clearStoredAuth,
  exchangeJwt,
  getStoredAuth,
  isJwt,
  onAuthRequired,
  storeAuth,
} from "./auth";
import { Client } from "./client";

describe("auth", () => {
  afterEach(() => {
    clearStoredAuth();
  });

  it("Should tell JWTs from Quickwit tokens", () => {
    expect(
      isJwt("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"),
    ).toBe(true);
    expect(isJwt("En0KEwoFYWxpY2UYAyIICgYIBBICGAgSJAgAEiCZ")).toBe(false);
  });

  it("Should drop expired tokens", () => {
    storeAuth({ token: "valid", expiresAt: "2999-01-01T00:00:00Z" });
    expect(getStoredAuth()?.token).toBe("valid");
    expect(authorizationHeaders()).toEqual({ Authorization: "Bearer valid" });
    storeAuth({ token: "expired", expiresAt: "2000-01-01T00:00:00Z" });
    expect(getStoredAuth()).toBeNull();
    expect(authorizationHeaders()).toEqual({});
  });

  it("Should send the token and report unauthenticated calls", async () => {
    const mockFetch = jest.fn((_url: string, _options?: RequestInit) =>
      Promise.resolve({
        ok: false,
        status: 401,
        text: () =>
          Promise.resolve('{"message": "authorization token missing"}'),
      }),
    );
    (global as any).fetch = mockFetch;
    const authRequiredListener = jest.fn();
    const unsubscribe = onAuthRequired(authRequiredListener);

    storeAuth({ token: "some-token" });
    await expect(new Client().listIndexes()).rejects.toMatchObject({
      status: 401,
    });
    const options = mockFetch.mock.calls[0]?.[1] as RequestInit;
    expect(options.headers).toMatchObject({
      Authorization: "Bearer some-token",
    });
    expect(authRequiredListener).toHaveBeenCalledTimes(1);
    unsubscribe();
  });

  it("Should exchange JWTs", async () => {
    const mockFetch = jest.fn((_url: string, _options?: RequestInit) =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            token: "quickwit-token",
            user: "alice",
            roles: ["reader"],
            expires_at: "2999-01-01T00:00:00Z",
          }),
      }),
    );
    (global as any).fetch = mockFetch;
    const auth = await exchangeJwt("a.b.c", "http://localhost:7280");
    expect(auth).toEqual({
      token: "quickwit-token",
      user: "alice",
      roles: ["reader"],
      expiresAt: "2999-01-01T00:00:00Z",
    });
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:7280/api/v1/auth/token",
      expect.objectContaining({ method: "POST" }),
    );
    const options = mockFetch.mock.calls[0]?.[1] as RequestInit;
    expect(options.headers).toMatchObject({ Authorization: "Bearer a.b.c" });
  });
});
