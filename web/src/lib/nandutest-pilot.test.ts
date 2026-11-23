import { describe, expect, it } from "vitest";

import { isPilotApprovalTicketValid } from "./nandutest-pilot";

describe("pilot approval reference validation", () => {
  it.each([
    "CHG-2026-00123",
    "Autorización de auditoría #2026-011",
    "Aprobación de Ñandutest",
    "Prueba (CISO), solicitud 03/11/2026",
    "A1234567",
  ])("accepts valid human-readable references: %s", (value) => {
    expect(isPilotApprovalTicketValid(value)).toBe(true);
  });

  it.each([
    "",
    "abc",
    "#12345678",
    "Autorización\ninterna 2026",
    "A\t1234567",
    "A<script>12345",
    "á".repeat(129),
  ])("rejects invalid or unsafe references", (value) => {
    expect(isPilotApprovalTicketValid(value)).toBe(false);
  });
});
