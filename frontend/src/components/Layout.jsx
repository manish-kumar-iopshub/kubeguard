import { NavLink } from "react-router-dom";

const NAV = [
  { to: "/", label: "Dashboard", icon: "◈" },
  { to: "/unhealthy-pods", label: "Unhealthy Pods", icon: "⚠" },
  { to: "/secret-leakage", label: "Secret Leakage", icon: "⛨" },
  { to: "/deployment-risk", label: "Deployment Risk", icon: "◆" },
];

function SideLink({ to, label, icon }) {
  return (
    <NavLink
      to={to}
      end={to === "/"}
      className={({ isActive }) =>
        `flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
          isActive
            ? "bg-indigo-600 text-white"
            : "text-slate-300 hover:bg-slate-700 hover:text-white"
        }`
      }
    >
      <span className="text-lg">{icon}</span>
      {label}
    </NavLink>
  );
}

export default function Layout({ children }) {
  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="w-64 bg-slate-800 flex flex-col shrink-0">
        <div className="px-5 py-5 border-b border-slate-700">
          <h1 className="text-xl font-bold text-white tracking-tight">
            KubeGuard
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Kubernetes Security Scanner
          </p>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV.map((n) => (
            <SideLink key={n.to} {...n} />
          ))}
        </nav>
      </aside>
      <main className="flex-1 overflow-y-auto bg-gray-50 p-6">{children}</main>
    </div>
  );
}
