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
      const auth = properties.auth_method;
      if (typeof auth === "string") chips.push(auth === "none" ? "no-auth" : auth);
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
      if (typeof sensitivity === "string") chips.push(sensitivity);
      break;
    }
    case "Host": {
      const hostname = properties.hostname;
      if (typeof hostname === "string") chips.push(hostname);
      else {
        const ip = properties.ip;
        if (typeof ip === "string") chips.push(ip);
      }
      break;
    }
    case "Credential": {
      const type = properties.type;
      if (typeof type === "string") chips.push(type);
      if (properties.is_exposed === true) chips.push("exposed");
      break;
    }
    case "A2AAgent": {
      const auth = properties.auth_method;
      if (typeof auth === "string") chips.push(auth === "none" ? "no-auth" : auth);
      if (properties.is_signed === true) chips.push("signed");
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
