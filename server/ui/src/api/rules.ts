import { api } from "./client";

export interface RuleInfo {
  id: string;
  name: string;
  description: string;
  version: number;
  enabled: boolean;
  severity: string;
  collector: string;
  targets: string[];
  matcher_type: string;
  owasp: string[];
  tags: string[];
  source: string;
  test_count: number;
}

export interface MatcherSpec {
  Type: string;
  Pattern?: string;
  Keywords?: string[];
  Prefixes?: string[];
  CaseInsensitive?: boolean;
  MatchMode?: string;
  Operator?: string;
  Matchers?: MatcherSpec[];
  Charset?: string;
  Threshold?: number;
  MinLength?: number;
}

export interface TestCase {
  Input: string;
  ShouldMatch: boolean;
  Description: string;
}

export interface RuleDetail extends RuleInfo {
  matcher: MatcherSpec;
  tests: TestCase[];
}

export async function fetchRules(params?: {
  collector?: string;
  severity?: string;
  tag?: string;
}): Promise<{ rules: RuleInfo[]; total: number }> {
  const searchParams: Record<string, string> = {};
  if (params?.collector) searchParams["collector"] = params.collector;
  if (params?.severity) searchParams["severity"] = params.severity;
  if (params?.tag) searchParams["tag"] = params.tag;
  return api
    .get("rules", { searchParams })
    .json<{ rules: RuleInfo[]; total: number }>();
}

export async function fetchRuleDetail(id: string): Promise<RuleDetail> {
  return api.get(`rules/${encodeURIComponent(id)}`).json<RuleDetail>();
}
