export interface DashboardProjectionIdentity {
  scanId: string;
  revision: number;
}

export function sameDashboardProjection(
  ...identities: Array<DashboardProjectionIdentity | null | undefined>
): boolean {
  if (identities.length === 0 || identities.some((identity) => !identity)) {
    return false;
  }
  const expected = identities[0]!;
  return identities.every(
    (identity) =>
      identity!.scanId === expected.scanId &&
      identity!.revision === expected.revision,
  );
}
