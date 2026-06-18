import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard,
  Compass,
  AlertTriangle,
  ScanSearch,
  BookOpen,
  ShieldCheck,
  PanelRight,
} from "lucide-react";
import { api } from "@/api/client";
import type { HealthResponse } from "@/api/types";
import { useUIStore } from "@/store/ui";
import { cn } from "@/lib/utils";

const navItems = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/explorer", label: "Explorer", icon: Compass },
  { to: "/findings", label: "Findings", icon: AlertTriangle },
  { to: "/scans", label: "Scans", icon: ScanSearch },
  { to: "/queries", label: "Queries", icon: BookOpen },
  { to: "/rules", label: "Rules", icon: ShieldCheck },
];

interface HealthLedProps {
  label: string;
  ok: boolean;
}

function HealthLed({ label, ok }: HealthLedProps) {
  return (
    <span className="flex items-center gap-1.5">
      <span
        className={cn("h-1.5 w-1.5 rounded-[1px]", ok ? "bg-emerald-500 animate-led-pulse" : "bg-destructive")}
        style={ok ? { boxShadow: "0 0 6px -1px #3FB950" } : undefined}
      />
      <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</span>
    </span>
  );
}

export function NavBar() {
  const location = useLocation();
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const sidebarOpen = useUIStore((s) => s.sidebarOpen);
  const suppressSidebarToggle = location.pathname.startsWith("/explorer");
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.get("health").json<HealthResponse>(),
    refetchInterval: 30_000,
  });

  const neo4jOk = (health?.neo4j ?? "").toLowerCase() === "ok";
  const postgresOk = (health?.postgres ?? "").toLowerCase() === "ok";

  return (
    <header className="flex h-12 items-center border-b border-border bg-carbon-900 px-4">
      <div className="mr-7 flex items-center gap-2">
        <img src="/logo-192.png" alt="AgentHound" className="h-6 w-6" />
        <span className="font-mono text-sm font-bold uppercase tracking-[0.1em] text-foreground">
          Agent<span className="text-primary">Hound</span>
        </span>
      </div>
      <nav className="flex items-center gap-0.5">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-1.5 rounded-[3px] px-2.5 py-1.5 font-mono text-[11px] uppercase tracking-[0.08em] transition-colors",
                isActive
                  ? "bg-primary/10 text-primary shadow-[inset_0_-2px_0_0_#F5A623]"
                  : "text-muted-foreground hover:bg-white/[0.04] hover:text-foreground",
              )
            }
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="ml-auto flex items-center gap-4">
        {!suppressSidebarToggle && (
          <button
            onClick={toggleSidebar}
            className={cn(
              "flex h-7 w-7 items-center justify-center rounded-[3px] text-muted-foreground transition-colors hover:bg-white/[0.04] hover:text-foreground",
              sidebarOpen && "bg-primary/10 text-primary",
            )}
            title="Toggle Inspector (i)"
          >
            <PanelRight className="h-4 w-4" />
          </button>
        )}
        <div className="hidden items-center gap-3 sm:flex">
          <HealthLed label="Neo4j" ok={neo4jOk} />
          <HealthLed label="PG" ok={postgresOk} />
        </div>
      </div>
    </header>
  );
}
