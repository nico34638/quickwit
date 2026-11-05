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
import SearchOffIcon from "@mui/icons-material/SearchOff";
import SentimentVeryDissatisfiedIcon from "@mui/icons-material/SentimentVeryDissatisfied";
import { Box, Button, Typography } from "@mui/material";
import { useAuth } from "../providers/AuthProvider";
import { ResponseError } from "../utils/models";

function AccessDenied({ message }: { message: string | null }) {
  const { identity, signOut } = useAuth();
  const roles = identity?.roles ?? [];
  return (
    <>
      <LockOutlinedIcon sx={{ fontSize: 60 }} color="action" />
      <Typography variant="h6" sx={{ pt: 2 }}>
        Access denied
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ pt: 1 }}>
        {roles.length > 0
          ? `Your roles (${roles.join(", ")}) do not allow this operation.`
          : "Your token does not grant any role allowing this operation."}
      </Typography>
      {message !== null && message !== "permission denied" && (
        <Typography variant="caption" color="text.secondary" sx={{ pt: 1 }}>
          {message}
        </Typography>
      )}
      {identity?.authorization_enabled && (
        <Button sx={{ mt: 2 }} onClick={signOut}>
          Sign in as another user
        </Button>
      )}
    </>
  );
}

// The search API reports the indexes that the user cannot read as not found, so as not to disclose
// their existence: with authorization, "not found" may also mean "not readable".
function IndexNotFound({ message }: { message: string }) {
  const { identity, signOut } = useAuth();
  const isAuthorizationEnabled = identity?.authorization_enabled ?? false;
  const roles = identity?.roles ?? [];
  return (
    <>
      <SearchOffIcon sx={{ fontSize: 60 }} color="action" />
      <Typography variant="h6" sx={{ pt: 2 }}>
        Index not found
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ pt: 1 }}>
        {isAuthorizationEnabled
          ? `It does not exist, or your roles (${roles.join(", ") || "none"}) do not allow reading it.`
          : "It does not exist."}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ pt: 1 }}>
        {message}
      </Typography>
      {isAuthorizationEnabled && (
        <Button sx={{ mt: 2 }} onClick={signOut}>
          Sign in as another user
        </Button>
      )}
    </>
  );
}

function GenericError({ status, message }: ResponseError) {
  const isMissingSearcher =
    message !== null && message.includes("No search node available.");
  return (
    <>
      <SentimentVeryDissatisfiedIcon sx={{ fontSize: 60 }} />
      {isMissingSearcher ? (
        <Box sx={{ fontSize: 16, pt: 2 }}>
          Your cluster does not contain any search node. You need at least one
          search node.
        </Box>
      ) : (
        <>
          <Box sx={{ fontSize: 16, pt: 2 }}>
            {status && <span>Status: {status}</span>}
          </Box>
          <Box sx={{ fontSize: 14, pt: 1, alignItems: "center" }}>
            Error: {message}
          </Box>
        </>
      )}
    </>
  );
}

// 401 responses bring back the sign-in page (see `AuthProvider`): only the other errors are
// displayed here.
export default function ErrorResponseDisplay(error: ResponseError) {
  return (
    <Box
      sx={{
        pt: 2,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        textAlign: "center",
      }}
    >
      {error.status === 403 ? (
        <AccessDenied message={error.message} />
      ) : error.status === 404 &&
        error.message !== null &&
        error.message.includes("could not find indexes matching") ? (
        <IndexNotFound message={error.message} />
      ) : (
        <GenericError {...error} />
      )}
    </Box>
  );
}
