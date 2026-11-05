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
  Alert,
  Box,
  Button,
  CircularProgress,
  CssBaseline,
  ThemeProvider,
} from "@mui/material";
import { Navigate, Route, Routes } from "react-router";
import { FullBoxContainer } from "../components/LayoutUtils";
import SideBar from "../components/SideBar";
import TopBar from "../components/TopBar";
import { AuthProvider, useAuth } from "../providers/AuthProvider";
import { LocalStorageProvider } from "../providers/LocalStorageProvider";
import { theme } from "../utils/theme";
import ApiView from "./ApiView";
import ClusterView from "./ClusterView";
import IndexesView from "./IndexesView";
import IndexView from "./IndexView";
import NodeInfoView from "./NodeInfoView";
import SearchView from "./SearchView";
import SignInView from "./SignInView";

function CenteredBox({ children }: { children: React.ReactNode }) {
  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        width: "100%",
        minHeight: "100vh",
        gap: 2,
      }}
    >
      {children}
    </Box>
  );
}

// Displays the app once the identity of the user is known, the sign-in page otherwise.
function AppContent() {
  const { state, hasClusterRight, refresh } = useAuth();
  if (state.status === "loading") {
    return (
      <CenteredBox>
        <CircularProgress />
      </CenteredBox>
    );
  }
  if (state.status === "signed-out") {
    return <SignInView reason={state.reason} />;
  }
  if (state.status === "error") {
    return (
      <CenteredBox>
        <Alert severity="error">
          Failed to reach the Quickwit cluster: {state.message}
        </Alert>
        <Button onClick={refresh}>Retry</Button>
      </CenteredBox>
    );
  }
  // Remounted when the user changes: the views fetch their data again with the new token.
  const userKey = state.identity.user ?? state.storedAuth?.token ?? "anonymous";
  return (
    <FullBoxContainer key={userKey} sx={{ flexDirection: "row", p: 0 }}>
      <TopBar />
      <SideBar />
      <Routes>
        <Route path="/" element={<Navigate to="/search" />} />
        <Route path="search" element={<SearchView />} />
        <Route path="indexes" element={<IndexesView />} />
        <Route path="indexes/:indexId" element={<IndexView />} />
        {hasClusterRight && <Route path="cluster" element={<ClusterView />} />}
        {hasClusterRight && (
          <Route path="node-info" element={<NodeInfoView />} />
        )}
        <Route path="api-playground" element={<ApiView />} />
        <Route path="*" element={<Navigate to="/search" />} />
      </Routes>
    </FullBoxContainer>
  );
}

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <LocalStorageProvider>
          <AppContent />
        </LocalStorageProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
