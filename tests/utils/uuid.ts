import { describe, it, expect } from "vitest";
import { generateUUID } from "../../src/utils/uuid";

describe("generateUUID", () => {
  it("returns uppercase UUID", () => {
    const id = generateUUID();
    expect(id).toMatch(
      /^[0-9A-F-]{36}$/
    );
  });
});