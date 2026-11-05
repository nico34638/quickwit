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
import { fireEvent, render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router";
import App from "./views/App";

const AUTHORIZATION_DISABLED = {
  authorization_enabled: false,
  user: null,
  roles: [],
  node: false,
  grants: [],
  cluster: true,
};

const READER = {
  authorization_enabled: true,
  user: "bob",
  roles: ["reader"],
  node: false,
  grants: [{ rights: ["index:read"], indexes: ["*"] }],
  cluster: false,
};

// Answers `/auth/whoami` with `whoami(headers)`, and the other API calls with an empty list.
function mockFetch(whoami) {
  global.fetch = jest.fn((url, options) => {
    const { status, body } = url.includes("auth/whoami")
      ? whoami(options?.headers ?? {})
      : { status: 200, body: [] };
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    });
  });
}

function renderApp() {
  render(
    <BrowserRouter>
      <App />
    </BrowserRouter>,
  );
}

describe("App", () => {
  afterEach(() => {
    localStorage.clear();
  });

  it("Should display side bar links", async () => {
    mockFetch(() => ({ status: 200, body: AUTHORIZATION_DISABLED }));
    renderApp();
    expect(await screen.findByText(/Discover/)).toBeInTheDocument();
    expect(screen.getByText(/Query editor/)).toBeInTheDocument();
    expect(screen.getByText(/Admin/)).toBeInTheDocument();
    expect(screen.getByText(/^Cluster$/)).toBeInTheDocument();
    expect(
      screen.queryByText(/requires authorization/),
    ).not.toBeInTheDocument();
  });

  it("Should ask for a token, then adapt to the rights of the user", async () => {
    mockFetch((headers) =>
      headers.Authorization === "Bearer reader-token"
        ? { status: 200, body: READER }
        : { status: 401, body: { message: "authorization token missing" } },
    );
    renderApp();
    expect(
      await screen.findByText(/This Quickwit cluster requires authorization/),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Token/), {
      target: { value: "reader-token" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    // The user menu shows the user, and the pages requiring the `cluster` right are hidden.
    expect(await screen.findByText("bob")).toBeInTheDocument();
    expect(screen.getByText(/Query editor/)).toBeInTheDocument();
    expect(screen.queryByText(/^Cluster$/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Node info/)).not.toBeInTheDocument();
  });

  it("Should reject an invalid token", async () => {
    mockFetch(() => ({
      status: 401,
      body: { message: "invalid authorization token" },
    }));
    renderApp();
    fireEvent.change(await screen.findByLabelText(/Token/), {
      target: { value: "forged-token" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText(/not valid for this cluster/),
    ).toBeInTheDocument();
    expect(localStorage.getItem("quickwitAuth")).toBeNull();
  });
});
