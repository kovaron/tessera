import { NavLink } from "react-router-dom";
import StatusBadge from "./StatusBadge";
import logo from "@/assets/logo.png";

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
    <aside className="w-56 border-r p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2 mb-1">
        <img src={logo} alt="" className="w-7 h-7 rounded-md" />
        <span className="font-semibold tracking-tight">Tessera</span>
      </div>
      <StatusBadge />
      <nav className="mt-2 flex flex-col gap-1">
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
