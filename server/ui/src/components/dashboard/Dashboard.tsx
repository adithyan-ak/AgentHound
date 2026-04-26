import { StatCards } from "./StatCards";
import { RiskChart } from "./RiskChart";
import { AuthCoverage } from "./AuthCoverage";
import { TopRiskyEntities } from "./TopRiskyEntities";
import { CredentialExposure } from "./CredentialExposure";
import { CrossProtocol } from "./CrossProtocol";
import { TopFindings } from "./TopFindings";
import { RecentScans } from "./RecentScans";

export function Dashboard() {
  return (
    <div className="space-y-6 p-6">
      <h2 className="text-lg font-semibold text-foreground">Dashboard</h2>
      <StatCards />
      <div className="grid gap-6 lg:grid-cols-2">
        <RiskChart />
        <TopRiskyEntities />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <AuthCoverage />
        <CredentialExposure />
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <CrossProtocol />
        <TopFindings />
      </div>
      <RecentScans />
    </div>
  );
}
