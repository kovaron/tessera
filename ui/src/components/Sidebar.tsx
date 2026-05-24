import { NavLink } from "react-router-dom";
import StatusBadge from "./StatusBadge";

const items = [
  { to: "/", label: "Dashboard" },
  { to: "/upstreams", label: "Upstreams" },
  { to: "/policies", label: "Policies" },
  { to: "/tokens", label: "Tokens" },
  { to: "/audit", label: "Audit Log" },
  { to: "/settings", label: "Settings" },
];

export default function Sidebar() {
  return (
    <aside className="w-56 border-r p-4 flex flex-col gap-2">
      <StatusBadge />
      <nav className="mt-4 flex flex-col gap-1">
        {items.map((it) => (
          <NavLink
            key={it.to}
            to={it.to}
            end={it.to === "/"}
            className={({ isActive }) =>
              `px-3 py-2 rounded text-sm ${isActive ? "bg-accent" : "hover:bg-accent/50"}`
            }
          >
            {it.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
