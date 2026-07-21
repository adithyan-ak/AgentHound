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
import { FEEDBACK, SEVERITY, SIGNAL_OK } from "@shared/theme/tokens";

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
  state: "ok" | "unavailable" | "unknown" | "stale";
}

function HealthLed({ label, state }: HealthLedProps) {
  const color =
    state === "ok"
      ? SIGNAL_OK
      : state === "unavailable"
        ? SEVERITY.critical.solid
        : FEEDBACK.warning.solid;
  return (
    <span className="flex items-center gap-1.5" title={`${label}: ${state}`}>
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-[1px]",
          state === "ok" && "animate-led-pulse",
        )}
        style={{
          backgroundColor: color,
          boxShadow: state === "ok" ? `0 0 6px -1px ${SIGNAL_OK}` : undefined,
        }}
      />
      <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
        {label} {state === "ok" ? "" : state}
      </span>
    </span>
  );
}

export function NavBar() {
  const { data: health, isError } = useHealth();
  const healthState = (
    component: "neo4j" | "postgres",
  ): HealthLedProps["state"] => {
    if (isError) return health ? "stale" : "unknown";
    return health?.[component] ?? "unknown";
  };

  return (
    <header className="flex h-12 items-center border-b border-border bg-carbon-900 px-2 sm:px-4">
      <div className="mr-2 flex shrink-0 items-center gap-2 lg:mr-7">
        <img src="/logo-192.png" alt="AgentHound" className="h-6 w-6" />
        <span className="hidden font-mono text-sm font-bold uppercase tracking-[0.1em] text-foreground lg:inline">
          Agent<span className="text-primary">Hound</span>
        </span>
      </div>
      <nav
        aria-label="Primary"
        className="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto"
      >
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            aria-label={label}
            title={label}
            className={({ isActive }) =>
              cn(
                "flex shrink-0 items-center gap-1.5 rounded-[3px] px-2 py-1.5 font-mono text-[11px] uppercase tracking-[0.08em] transition-colors sm:px-2.5",
                isActive
                  ? "bg-primary/10 text-primary shadow-[inset_0_-2px_0_0_rgb(var(--phosphor-raw))]"
                  : "text-muted-foreground hover:bg-white/[0.04] hover:text-foreground",
              )
            }
          >
            <Icon className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">{label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="ml-auto flex shrink-0 items-center gap-4">
        <div className="hidden items-center gap-3 xl:flex">
          <HealthLed label="Neo4j" state={healthState("neo4j")} />
          <HealthLed label="PG" state={healthState("postgres")} />
        </div>
      </div>
    </header>
  );
}
