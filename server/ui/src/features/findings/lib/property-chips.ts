import {
  authMethodFromProperties,
  hasConfirmedAnonymousAccess,
} from "@entities/node";

function authChip(properties: Record<string, unknown>): string {
  if (hasConfirmedAnonymousAccess(properties)) return "no-auth";
  const method = authMethodFromProperties(properties);
  if (method === "localProcess") return "local-process";
  return method === "unknown" ? "auth-unknown" : method;
}

export function getPropertyChips(kind: string, properties: Record<string, unknown>): string[] {
  const chips: string[] = [];

  switch (kind) {
    case "AgentInstance": {
      const fw = properties.framework;
      if (typeof fw === "string") chips.push(fw);
      break;
    }
    case "MCPServer": {
      const transport = properties.transport;
      if (typeof transport === "string") chips.push(transport);
      chips.push(authChip(properties));
      const pinning = properties.pinning_status;
      if (typeof pinning === "string") chips.push(`pinning:${pinning}`);
      break;
    }
    case "MCPTool": {
      const caps = properties.capability_surface;
      if (Array.isArray(caps)) {
        for (const c of caps.slice(0, 2)) {
          if (typeof c === "string") chips.push(c);
        }
      }
      break;
    }
    case "MCPResource": {
      const scheme = properties.uri_scheme;
      if (typeof scheme === "string") chips.push(scheme + "://");
      const sensitivity = properties.sensitivity;
      chips.push(typeof sensitivity === "string" ? sensitivity : "unknown");
      break;
    }
    case "Host": {
      const hostname = properties.hostname;
      if (typeof hostname === "string") chips.push(hostname);
      else {
        const ip = properties.ip;
        if (typeof ip === "string") chips.push(ip);
      }
      const scope = properties.scope;
      if (typeof scope === "string") chips.push(scope);
      break;
    }
    case "Credential": {
      const type = properties.type;
      if (typeof type === "string") chips.push(type);
      if (
        properties.exposure_status === "exposed" &&
        properties.material_status === "observed"
      ) {
        chips.push("exposed");
      } else if (typeof properties.material_status === "string") {
        chips.push(`material:${properties.material_status}`);
      } else if (
        properties.is_exposed === true &&
        properties.merge_key !== "identity"
      ) {
        chips.push("exposed");
      }
      break;
    }
    case "A2AAgent": {
      chips.push(authChip(properties));
      const signature = properties.signature_verification_status;
      if (typeof signature === "string") chips.push(`signature:${signature}`);
      else chips.push("signature:unknown");
      break;
    }
    case "Identity": {
      const type = properties.type;
      if (typeof type === "string") chips.push(type);
      break;
    }
    case "InstructionFile": {
      const type = properties.type;
      if (typeof type === "string") chips.push(type);
      if (properties.is_suspicious === true) chips.push("suspicious");
      break;
    }
    case "ConfigFile": {
      const client = properties.client;
      if (typeof client === "string") chips.push(client);
      break;
    }
  }

  return chips;
}
