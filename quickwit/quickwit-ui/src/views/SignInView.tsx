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

import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { useState } from "react";
import quickwitLogoUrl from "../assets/img/quickwit-logo-with-title.svg";
import { SignedOutReason, useAuth } from "../providers/AuthProvider";
import { isJwt } from "../services/auth";

const REASON_MESSAGES: Record<SignedOutReason, string> = {
  "no-token": "This Quickwit cluster requires authorization.",
  expired: "Your session expired: sign in again.",
  "signed-out": "You are signed out.",
};

function inputKind(input: string): string | null {
  const trimmedInput = input.trim();
  if (trimmedInput === "") {
    return null;
  }
  if (isJwt(trimmedInput)) {
    return "Identity provider token (JWT): it will be exchanged for a Quickwit token.";
  }
  return "Quickwit token.";
}

// Full-page sign-in, displayed instead of the app while no valid token is available.
function SignInView({ reason }: { reason: SignedOutReason }) {
  const { signIn } = useAuth();
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const onSubmit = async (event: { preventDefault: () => void }) => {
    event.preventDefault();
    if (input.trim() === "") {
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await signIn(input);
    } catch (signInError) {
      setError((signInError as Error).message);
      setIsSubmitting(false);
    }
  };

  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        width: "100%",
        minHeight: "100vh",
        backgroundColor: "#f5f5f7",
        p: 2,
      }}
    >
      <Paper
        component="form"
        onSubmit={onSubmit}
        elevation={2}
        sx={{ width: "100%", maxWidth: 520, p: 4 }}
      >
        <Box sx={{ display: "flex", justifyContent: "center", mb: 3 }}>
          <img src={quickwitLogoUrl} alt="Quickwit" height="32px" />
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
          <LockOutlinedIcon color="primary" />
          <Typography variant="h6">Sign in</Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {REASON_MESSAGES[reason]}
        </Typography>
        <TextField
          autoFocus
          fullWidth
          multiline
          minRows={4}
          maxRows={8}
          label="Token"
          placeholder="Paste a token from your identity provider (JWT) or a Quickwit token"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              onSubmit(event);
            }
          }}
          disabled={isSubmitting}
          helperText={inputKind(input) ?? " "}
          slotProps={{
            input: { sx: { fontFamily: "monospace", fontSize: 12 } },
          }}
        />
        {error !== null && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}
        <Button
          type="submit"
          variant="contained"
          fullWidth
          sx={{ mt: 3 }}
          disabled={isSubmitting || input.trim() === ""}
          startIcon={
            isSubmitting ? <CircularProgress size={16} color="inherit" /> : null
          }
        >
          Sign in
        </Button>
        <Typography
          variant="caption"
          color="text.secondary"
          component="p"
          sx={{ mt: 2 }}
        >
          The token is kept in the local storage of this browser until you sign
          out or it expires.
        </Typography>
      </Paper>
    </Box>
  );
}

export default SignInView;
