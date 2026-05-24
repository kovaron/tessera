import { createBrowserRouter } from "react-router-dom";
import Dashboard from "./screens/Dashboard";
import Upstreams from "./screens/Upstreams";
import Policies from "./screens/Policies";
import Tokens from "./screens/Tokens";
import AuditLog from "./screens/AuditLog";
import Settings from "./screens/Settings";
import App from "./App";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "upstreams", element: <Upstreams /> },
      { path: "policies", element: <Policies /> },
      { path: "tokens", element: <Tokens /> },
      { path: "audit", element: <AuditLog /> },
      { path: "settings", element: <Settings /> },
    ],
  },
]);
