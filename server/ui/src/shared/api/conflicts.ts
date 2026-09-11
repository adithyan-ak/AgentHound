export class ProjectionConflictError extends Error {
  readonly code = "PROJECTION_CONFLICT";

  constructor(
    message = "published graph projection changed or is unavailable",
    readonly reason?: string,
  ) {
    super(message);
    this.name = "ProjectionConflictError";
  }
}
