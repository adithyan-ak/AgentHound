export interface FindingDetailErrorPresentation {
  kind: "not_found" | "unavailable";
  title: string;
  message: string;
}

export function findingDetailErrorPresentation(
  error: unknown,
): FindingDetailErrorPresentation {
  if (httpStatus(error) === 404) {
    return {
      kind: "not_found",
      title: "Finding not found",
      message:
        "This finding is not present in the published snapshot. It may have been superseded or the URL may be invalid.",
    };
  }
  return {
    kind: "unavailable",
    title: "Finding detail unavailable",
    message:
      "The finding detail request failed. No conclusion about whether the finding exists or was resolved can be drawn from this error.",
  };
}

function httpStatus(error: unknown): number | undefined {
  if (typeof error !== "object" || error == null || !("response" in error)) {
    return undefined;
  }
  const response = (error as { response?: unknown }).response;
  if (
    typeof response !== "object" ||
    response == null ||
    !("status" in response)
  ) {
    return undefined;
  }
  const status = (response as { status?: unknown }).status;
  return typeof status === "number" ? status : undefined;
}
