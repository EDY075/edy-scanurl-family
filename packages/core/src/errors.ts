export class DomainInvariantError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "DomainInvariantError";
  }
}
