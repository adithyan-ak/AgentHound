import { StatCards } from "./StatCards";
import { RiskChart } from "./RiskChart";
import { AuthCoverage } from "./AuthCoverage";
import { TopFindings } from "./TopFindings";
import { RecentScans } from "./RecentScans";

export function Dashboard() {
  return (
    <div className="space-y-6 p-6">
      <h2 className="text-lg font-semibold text-foreground">Dashboard</h2>
      <StatCards />
      <div className="grid gap-6 lg:grid-cols-2">
        <RiskChart />
        <AuthCoverage />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <TopFindings />
        <RecentScans />
      </div>
    </div>
  );
}
