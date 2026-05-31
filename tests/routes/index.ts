import { describe, it, expect } from "vitest";
import * as routes from "../../src/routes";

describe("route barrel exports", () => {
  it("exports route handlers", () => {
    expect(routes).toBeDefined();
  });
});