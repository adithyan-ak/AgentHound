import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Compass,
  AlertTriangle,
  ScanSearch,
  BookOpen,
  ShieldCheck,
} from "lucide-react";
import { useHealth } from "@entities/health";
import { cn } from "@shared/lib/utils";
import { SIGNAL_OK } from "@shared/theme/tokens";

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
        style={ok ? { boxShadow: `0 0 6px -1px ${SIGNAL_OK}` } : undefined}
      />
      <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</span>
    </span>
  );
}

export function NavBar() {
  const { data: health } = useHealth();

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
                  ? "bg-primary/10 text-primary shadow-[inset_0_-2px_0_0_rgb(var(--phosphor-raw))]"
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
        <div className="hidden items-center gap-3 sm:flex">
          <HealthLed label="Neo4j" ok={neo4jOk} />
          <HealthLed label="PG" ok={postgresOk} />
        </div>
      </div>
    </header>
  );
}
