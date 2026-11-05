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

import { describe, expect, it } from "@jest/globals";
import { render, screen } from "@testing-library/react";
import ErrorResponseDisplay from "./ResponseErrorDisplay";

describe("ErrorResponseDisplay", () => {
  it("Should explain access denied errors", () => {
    render(<ErrorResponseDisplay status={403} message="permission denied" />);
    expect(screen.getByText("Access denied")).toBeInTheDocument();
  });

  it("Should explain indexes not found", () => {
    render(
      <ErrorResponseDisplay
        status={404}
        message={'could not find indexes matching the IDs `["secret"]`'}
      />,
    );
    expect(screen.getByText("Index not found")).toBeInTheDocument();
    expect(screen.getByText(/could not find indexes/)).toBeInTheDocument();
  });

  it("Should display the other errors", () => {
    render(<ErrorResponseDisplay status={500} message="internal error" />);
    expect(screen.getByText(/Status: 500/)).toBeInTheDocument();
    expect(screen.getByText(/internal error/)).toBeInTheDocument();
  });
});
