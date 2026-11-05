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

import {
  createContext,
  PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  clearStoredAuth,
  exchangeJwt,
  getStoredAuth,
  Identity,
  isJwt,
  onAuthRequired,
  StoredAuth,
  storeAuth,
} from "../services/auth";
import { Client } from "../services/client";
import { ResponseError } from "../utils/models";

// Why the sign-in page is displayed.
export type SignedOutReason = "no-token" | "expired" | "signed-out";

export type AuthState =
  | { status: "loading" }
  // Signed in, or authorization is disabled (`identity.authorization_enabled` is false).
  | { status: "ready"; identity: Identity; storedAuth: StoredAuth | null }
  | { status: "signed-out"; reason: SignedOutReason }
  // The cluster cannot be reached.
  | { status: "error"; message: string };

type AuthContextValue = {
  state: AuthState;
  // Identity of the signed-in user, `null` while signed out.
  identity: Identity | null;
  // Whether the `cluster` right is granted (always, when authorization is disabled).
  hasClusterRight: boolean;
  refresh: () => Promise<void>;
  // Signs in with a Quickwit token or a JWT (exchanged). Rejects with a user-facing message.
  signIn: (tokenOrJwt: string) => Promise<void>;
  signOut: () => void;
};

const AuthContext = createContext<AuthContextValue>({
  // Without provider (unit tests of the views), the UI behaves as if authorization was disabled.
  state: { status: "loading" },
  identity: null,
  hasClusterRight: true,
  refresh: async () => undefined,
  signIn: async () => undefined,
  signOut: () => undefined,
});

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}

function exchangeErrorMessage(error: ResponseError): string {
  switch (error.status) {
    case 401:
      return `The identity provider token was rejected: ${error.message}`;
    case 403:
      return "Your identity provider groups do not grant any Quickwit role.";
    case 404:
      return (
        "This node does not exchange identity provider tokens. Open the UI of the node " +
        "serving the exchange, or paste a Quickwit token."
      );
    case 503:
      return `The identity provider is unavailable: ${error.message}`;
    default:
      return error.message ?? "Failed to exchange the token.";
  }
}

export const AuthProvider = ({ children }: PropsWithChildren) => {
  const [state, setState] = useState<AuthState>({ status: "loading" });
  const client = useMemo(() => new Client(), []);

  const refresh = useCallback(async () => {
    try {
      const identity = await client.whoami();
      setState({ status: "ready", identity, storedAuth: getStoredAuth() });
    } catch (error) {
      const responseError = error as ResponseError;
      if (responseError.status === 401) {
        const hadToken = getStoredAuth() !== null;
        clearStoredAuth();
        setState({
          status: "signed-out",
          reason: hadToken ? "expired" : "no-token",
        });
        return;
      }
      setState({
        status: "error",
        message:
          responseError.message ?? "Failed to reach the Quickwit cluster.",
      });
    }
  }, [client]);

  useEffect(() => {
    refresh();
    // Any API call rejected as unauthenticated (expired token) brings back the sign-in page.
    return onAuthRequired(() => {
      refresh();
    });
  }, [refresh]);

  const signIn = useCallback(
    async (tokenOrJwt: string) => {
      const input = tokenOrJwt.trim();
      let storedAuth: StoredAuth;
      if (isJwt(input)) {
        try {
          storedAuth = await exchangeJwt(input);
        } catch (error) {
          throw new Error(exchangeErrorMessage(error as ResponseError));
        }
      } else {
        storedAuth = { token: input };
      }
      storeAuth(storedAuth);
      try {
        const identity = await client.whoami();
        setState({ status: "ready", identity, storedAuth });
      } catch (error) {
        clearStoredAuth();
        const responseError = error as ResponseError;
        if (responseError.status === 401) {
          throw new Error(
            "This token is not valid for this cluster, or it expired.",
          );
        }
        throw new Error(responseError.message ?? "Failed to sign in.");
      }
    },
    [client],
  );

  const signOut = useCallback(() => {
    clearStoredAuth();
    setState({ status: "signed-out", reason: "signed-out" });
  }, []);

  const identity = state.status === "ready" ? state.identity : null;
  const value: AuthContextValue = {
    state,
    identity,
    hasClusterRight: identity === null || identity.cluster,
    refresh,
    signIn,
    signOut,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
