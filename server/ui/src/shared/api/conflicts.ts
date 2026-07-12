export class ProjectionConflictError extends Error {
  readonly code = "PROJECTION_CONFLICT";

  constructor(message = "published graph projection changed or is unavailable") {
    super(message);
    this.name = "ProjectionConflictError";
  }
}
