/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll } from "bun:test";
import { mapSeverityToLevel } from "../severity.js";
import type { OSVVulnerability, OSVSeverity } from "../schema.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("mapSeverityToLevel", () => {
	describe("database_specific.severity mapping", () => {
		test("should map CRITICAL to fatal", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: "CRITICAL",
				},
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should map HIGH to fatal", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: "HIGH",
				},
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should map MEDIUM to warn", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: "MEDIUM",
				},
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should map LOW to warn", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: "LOW",
				},
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle unknown severity strings", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: "UNKNOWN_SEVERITY",
				},
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle non-string severity values", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: 123,
				},
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});
	});

	describe("CVSS score mapping", () => {
		test("should map CVSS 3.1 score >= 7.0 to fatal", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should map CVSS score exactly 7.0 to fatal", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "7.0",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should map CVSS score < 7.0 to warn", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "6.9",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle CVSS vector strings with score at end", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/7.8",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should handle integer CVSS scores", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "8",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should handle multiple CVSS scores and use highest", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V2",
						score: "4.3",
					},
					{
						type: "CVSS_V3",
						score: "7.5",
					},
					{
						type: "CVSS_V31",
						score: "6.1",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal"); // Should use 7.5 as highest
		});

		test("should handle invalid CVSS scores gracefully", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "invalid-score",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should ignore non-CVSS severity types", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "EPSS",
						score: "0.95",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle out-of-range CVSS scores", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "15.0", // Invalid - CVSS max is 10.0
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle negative CVSS scores", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "-1.0",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});
	});

	describe("priority and fallback", () => {
		test("should prioritize database_specific.severity over CVSS", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				database_specific: {
					severity: "LOW", // Should result in warn (not MEDIUM which isn't a FatalSeverity)
				},
				severity: [
					{
						type: "CVSS_V3",
						score: "9.0", // Would result in fatal
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn"); // Should use database severity
		});

		test("should fall back to CVSS when no database severity", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "8.5",
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("fatal");
		});

		test("should default to warn when no severity information", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should default to warn when severity array is empty", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});
	});

	describe("edge cases", () => {
		test("should handle malformed severity objects", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: undefined as unknown as string, // Undefined score field
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle null/undefined severity array", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: null as unknown as OSVSeverity[],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});

		test("should handle complex CVSS vector without score", () => {
			const vuln: OSVVulnerability = {
				id: "TEST-001",
				severity: [
					{
						type: "CVSS_V3",
						score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // No score at end
					},
				],
			};

			const result = mapSeverityToLevel(vuln);
			expect(result).toBe("warn");
		});
	});
});
