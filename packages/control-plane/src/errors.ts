export class DomainError extends Error {
  constructor(
    readonly code:
      | "NOT_FOUND"
      | "CONFLICT"
      | "POLICY_DENIED"
      | "INVALID_STATE"
      | "INVALID_ARGUMENT",
    message: string
  ) {
    super(message);
    this.name = "DomainError";
  }
}
