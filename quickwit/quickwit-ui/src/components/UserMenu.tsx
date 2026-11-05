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

import AccountCircleOutlinedIcon from "@mui/icons-material/AccountCircleOutlined";
import LogoutIcon from "@mui/icons-material/Logout";
import {
  Box,
  Button,
  Chip,
  Divider,
  ListItemIcon,
  Menu,
  MenuItem,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { useAuth } from "../providers/AuthProvider";
import { Identity } from "../services/auth";

function displayName(identity: Identity): string {
  if (identity.node) {
    return "node token";
  }
  return identity.user ?? "anonymous token";
}

function formatExpiration(expiresAt: string | undefined): string | null {
  if (expiresAt === undefined) {
    return null;
  }
  const expiresAtDate = new Date(expiresAt);
  if (Number.isNaN(expiresAtDate.getTime())) {
    return null;
  }
  return expiresAtDate.toLocaleString();
}

// Signed-in user, roles, rights, and sign-out actions. Hidden when authorization is disabled.
const UserMenu = () => {
  const { state, identity, signOut } = useAuth();
  const [anchorElement, setAnchorElement] = useState<HTMLElement | null>(null);

  if (identity === null || !identity.authorization_enabled) {
    return null;
  }
  const storedAuth = state.status === "ready" ? state.storedAuth : null;
  const expiration = formatExpiration(storedAuth?.expiresAt);

  return (
    <>
      <Button
        color="inherit"
        startIcon={<AccountCircleOutlinedIcon />}
        onClick={(event) => setAnchorElement(event.currentTarget)}
        sx={{ textTransform: "none" }}
      >
        {displayName(identity)}
      </Button>
      <Menu
        anchorEl={anchorElement}
        open={anchorElement !== null}
        onClose={() => setAnchorElement(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        transformOrigin={{ vertical: "top", horizontal: "right" }}
      >
        <Box sx={{ px: 2, py: 1, maxWidth: 360 }}>
          <Typography variant="subtitle2">{displayName(identity)}</Typography>
          {identity.roles.length > 0 && (
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
              {identity.roles.map((role) => (
                <Chip key={role} label={role} size="small" />
              ))}
            </Box>
          )}
          <Box sx={{ mt: 1 }}>
            {identity.node && (
              <Typography variant="caption" component="p">
                All rights
              </Typography>
            )}
            {identity.grants.map((grant) => (
              <Typography
                key={`${grant.rights.join(",")} ${grant.indexes.join(",")}`}
                variant="caption"
                component="p"
                color="text.secondary"
              >
                {grant.rights.join(", ")} on {grant.indexes.join(", ")}
              </Typography>
            ))}
            {!identity.node && identity.grants.length === 0 && (
              <Typography variant="caption" component="p" color="error">
                Your roles grant no right.
              </Typography>
            )}
          </Box>
          {expiration !== null && (
            <Typography
              variant="caption"
              component="p"
              color="text.secondary"
              sx={{ mt: 1 }}
            >
              Expires on {expiration}
            </Typography>
          )}
        </Box>
        <Divider />
        <MenuItem
          onClick={() => {
            setAnchorElement(null);
            signOut();
          }}
        >
          <ListItemIcon>
            <LogoutIcon fontSize="small" />
          </ListItemIcon>
          Sign out or switch user
        </MenuItem>
      </Menu>
    </>
  );
};

export default UserMenu;
