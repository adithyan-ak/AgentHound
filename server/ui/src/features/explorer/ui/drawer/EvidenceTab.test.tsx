import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { APINode } from "@entities/graph/dto";
import { EvidenceTab } from "./EvidenceTab";

function server(properties: Record<string, unknown>): APINode {
  return { id: "server-1", kinds: ["MCPServer"], properties };
}

function agent(properties: Record<string, unknown>): APINode {
  return { id: "agent-1", kinds: ["A2AAgent"], properties };
}

describe("EvidenceTab MCP runtime evidence", () => {
  it("represents a successful MCP enumeration as direct verification", () => {
    render(
      <EvidenceTab
        node={server({
          status: "reachable",
          auth_method: "unknown",
          auth_assurance: "unknown",
          auth_evidence: "unknown",
          observed_auth_method: "none",
          observed_auth_assurance: "unauthenticated",
          observed_auth_evidence: "anonymous_probe_succeeded",
          effective_auth_method: "none",
          effective_auth_assurance: "unauthenticated",
          effective_auth_evidence: "anonymous_probe_succeeded",
          effective_auth_source: "observed",
        })}
      />,
    );

    expect(screen.getByText("Directly verified")).toBeInTheDocument();
    expect(screen.queryByText("Verification status unknown")).not.toBeInTheDocument();
    expect(screen.getByText("observed auth method")).toBeInTheDocument();
    expect(screen.getByText("observed auth evidence")).toBeInTheDocument();
    expect(screen.getAllByText("anonymous_probe_succeeded")).toHaveLength(2);
  });

  it("represents an unsuccessful MCP connection as failed verification", () => {
    render(
      <EvidenceTab
        node={server({
          status: "unreachable",
          error: "MCP operation failed; raw transport details omitted from artifact",
          observed_auth_method: "unknown",
          observed_auth_assurance: "unknown",
          observed_auth_evidence: "unknown",
        })}
      />,
    );

    expect(screen.getByText("Verification failed")).toBeInTheDocument();
    expect(screen.queryByText("Verification status unknown")).not.toBeInTheDocument();
  });

  it("does not let passive configuration evidence hide a failed probe", () => {
    render(
      <EvidenceTab
        node={server({
          status: "unreachable",
          configuration_observed: true,
          probe_status: "configured_unverified",
          error: "MCP operation failed; raw transport details omitted from artifact",
        })}
      />,
    );

    expect(screen.getByText("Verification failed")).toBeInTheDocument();
    expect(screen.queryByText("Configured, not verified")).not.toBeInTheDocument();
  });
});

describe("EvidenceTab A2A authentication probe evidence", () => {
  it("represents the exact anonymous read-only probe without claiming skill execution", () => {
    render(
      <EvidenceTab
        node={agent({
          auth_probe_method: "get_task_nonexistent",
          auth_probe_status: "anonymous_protocol_access",
          auth_probe_detail: "task_not_found_v1",
          observed_auth_method: "none",
          observed_auth_assurance: "unauthenticated",
          observed_auth_evidence: "anonymous_probe_succeeded",
          signature_verification_status: "valid_trusted",
          signature_key_source: "trusted_store",
          signature_key_trust: "trusted",
        })}
      />,
    );

    expect(screen.getByText("Directly verified")).toBeInTheDocument();
    expect(
      screen.getByText(/verifies anonymous protocol-handler access, not message submission or skill execution/i),
    ).toBeInTheDocument();
    expect(screen.getByText("auth probe method")).toBeInTheDocument();
    expect(screen.getByText("auth probe status")).toBeInTheDocument();
    expect(screen.getByText("signature verification status")).toBeInTheDocument();
    expect(screen.queryByText("Verification status unknown")).not.toBeInTheDocument();
  });

  it("distinguishes an observed authentication boundary from a failed service", () => {
    render(
      <EvidenceTab
        node={agent({
          auth_probe_method: "get_task_nonexistent",
          auth_probe_status: "authentication_required",
          auth_probe_detail: "http_unauthorized",
        })}
      />,
    );

    expect(screen.getByText("Authentication required")).toBeInTheDocument();
    expect(screen.getByText(/rejected the credential-free read-only probe/i)).toBeInTheDocument();
    expect(screen.queryByText("Verification failed")).not.toBeInTheDocument();
  });

  it("keeps an inconclusive protocol result explicitly unknown", () => {
    render(
      <EvidenceTab
        node={agent({
          auth_probe_method: "get_task_nonexistent",
          auth_probe_status: "unknown",
          auth_probe_detail: "method_not_supported",
        })}
      />,
    );

    expect(screen.getByText("Verification status unknown")).toBeInTheDocument();
    expect(screen.queryByText("Directly verified")).not.toBeInTheDocument();
    expect(screen.getByText("method_not_supported")).toBeInTheDocument();
  });

  it("does not trust an orphan anonymous status without the paired observation", () => {
    render(
      <EvidenceTab
        node={agent({
          auth_probe_method: "get_task_nonexistent",
          auth_probe_status: "anonymous_protocol_access",
        })}
      />,
    );

    expect(screen.getByText("Verification status unknown")).toBeInTheDocument();
    expect(screen.queryByText("Directly verified")).not.toBeInTheDocument();
  });

  it("does not trust otherwise complete A2A evidence without a canonical detail", () => {
    render(
      <EvidenceTab
        node={agent({
          auth_probe_method: "get_task_nonexistent",
          auth_probe_status: "anonymous_protocol_access",
          auth_probe_detail: "generic_not_found",
          observed_auth_method: "none",
          observed_auth_assurance: "unauthenticated",
          observed_auth_evidence: "anonymous_probe_succeeded",
        })}
      />,
    );

    expect(screen.getByText("Verification status unknown")).toBeInTheDocument();
    expect(screen.queryByText("Directly verified")).not.toBeInTheDocument();
  });

  it("does not label a noncanonical protected detail as an observed boundary", () => {
    render(
      <EvidenceTab
        node={agent({
          auth_probe_method: "get_task_nonexistent",
          auth_probe_status: "authentication_required",
          auth_probe_detail: "http_401",
        })}
      />,
    );

    expect(screen.getByText("Verification status unknown")).toBeInTheDocument();
    expect(screen.queryByText("Authentication required")).not.toBeInTheDocument();
  });
});
