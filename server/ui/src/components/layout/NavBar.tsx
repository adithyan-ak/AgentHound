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

  const isHealthy = health?.status === "healthy";

  return (
    <header className="flex h-12 items-center border-b bg-card px-4">
      <div className="flex items-center gap-2 mr-8">
        <img src="/logo-192.png" alt="AgentHound" className="h-6 w-6" />
        <span className="font-semibold text-sm">AgentHound</span>
      </div>
      <nav className="flex items-center gap-1">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors",
                isActive
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent",
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="ml-auto flex items-center gap-4">
        {!suppressSidebarToggle && (
          <button
            onClick={toggleSidebar}
            className={cn(
              "flex items-center justify-center h-7 w-7 rounded-md text-muted-foreground transition-colors hover:text-foreground hover:bg-accent",
              sidebarOpen && "text-primary bg-primary/10",
            )}
            title="Toggle Inspector (i)"
          >
            <PanelRight className="h-4 w-4" />
          </button>
        )}
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "h-2 w-2 rounded-full",
              isHealthy ? "bg-emerald-500" : "bg-destructive",
            )}
            title={isHealthy ? "All systems operational" : "Service degraded"}
          />
          <span className="text-xs text-muted-foreground">
            {isHealthy ? "Healthy" : "Degraded"}
          </span>
        </div>
      </div>
    </header>
  );
}
