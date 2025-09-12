/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll } from "bun:test";
import type { FatalSeverity } from "../types.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("Type Definitions", () => {
	describe("FatalSeverity type", () => {
		test("should accept valid CRITICAL severity", () => {
			const severity: FatalSeverity = "CRITICAL";
			expect(severity).toBe("CRITICAL");
		});

		test("should accept valid HIGH severity", () => {
			const severity: FatalSeverity = "HIGH";
			expect(severity).toBe("HIGH");
		});

		test("should be compatible with string literals", () => {
			function processSeverity(severity: FatalSeverity): string {
				return `Processing ${severity} severity`;
			}

			expect(processSeverity("CRITICAL")).toBe("Processing CRITICAL severity");
			expect(processSeverity("HIGH")).toBe("Processing HIGH severity");
		});

		test("should work in array contexts", () => {
			const severities: FatalSeverity[] = ["CRITICAL", "HIGH"];
			expect(severities).toHaveLength(2);
			expect(severities).toContain("CRITICAL");
			expect(severities).toContain("HIGH");
		});

		test("should work with conditional logic", () => {
			function isFatal(severity: string): severity is FatalSeverity {
				return severity === "CRITICAL" || severity === "HIGH";
			}

			expect(isFatal("CRITICAL")).toBe(true);
			expect(isFatal("HIGH")).toBe(true);
			expect(isFatal("MEDIUM")).toBe(false);
			expect(isFatal("LOW")).toBe(false);
		});
	});

	describe("Bun namespace extensions", () => {
		test("should extend Bun.semver with satisfies method", () => {
			// Test that the type extension doesn't break compilation
			expect(typeof Bun.semver.satisfies).toBe("function");
		});

		test("should work with actual semver operations", () => {
			// Test basic semver functionality that we rely on
			expect(Bun.semver.satisfies("1.2.3", "^1.0.0")).toBe(true);
			expect(Bun.semver.satisfies("2.0.0", "^1.0.0")).toBe(false);
		});

		test("should handle complex semver ranges", () => {
			expect(Bun.semver.satisfies("1.5.0", ">=1.0.0 <2.0.0")).toBe(true);
			expect(Bun.semver.satisfies("1.5.0", ">=1.0.0 <1.4.0")).toBe(false);
		});

		test("should handle edge cases in semver", () => {
			expect(Bun.semver.satisfies("1.0.0", "1.0.0")).toBe(true);
			expect(Bun.semver.satisfies("1.0.0", ">=1.0.0")).toBe(true);
			expect(Bun.semver.satisfies("1.0.0", ">1.0.0")).toBe(false);
		});
	});

	describe("Type compatibility", () => {
		test("should work with OSV vulnerability severity mapping", () => {
			// This tests the type system works correctly with our severity logic
			function mapOSVSeverity(severity: unknown): "fatal" | "warn" {
				if (typeof severity === "string") {
					const fatalSeverities: readonly FatalSeverity[] = [
						"CRITICAL",
						"HIGH",
					];
					if (fatalSeverities.includes(severity as FatalSeverity)) {
						return "fatal";
					}
				}
				return "warn";
			}

			expect(mapOSVSeverity("CRITICAL")).toBe("fatal");
			expect(mapOSVSeverity("HIGH")).toBe("fatal");
			expect(mapOSVSeverity("MEDIUM")).toBe("warn");
			expect(mapOSVSeverity("LOW")).toBe("warn");
			expect(mapOSVSeverity("UNKNOWN")).toBe("warn");
			expect(mapOSVSeverity(null)).toBe("warn");
			expect(mapOSVSeverity(undefined)).toBe("warn");
			expect(mapOSVSeverity(123)).toBe("warn");
		});

		test("should work with Bun Security types", () => {
			// Test compatibility with Bun.Security namespace types
			const mockPackage: Bun.Security.Package = {
				name: "test-package",
				version: "1.0.0",
				requestedRange: "^1.0.0",
				tarball:
					"https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
			};

			const mockAdvisory: Bun.Security.Advisory = {
				level: "fatal",
				package: "test-package",
				url: "https://github.com/advisories/GHSA-test",
				description: "Test vulnerability",
			};

			expect(mockPackage.name).toBe("test-package");
			expect(mockAdvisory.level).toBe("fatal");
		});

		test("should work with scanner interface", () => {
			// Test that scanner interface types work correctly
			const mockScanResult: Bun.Security.Advisory[] = [
				{
					level: "fatal",
					package: "vulnerable-pkg",
					url: "https://example.com/advisory",
					description: "Critical security issue",
				},
				{
					level: "warn",
					package: "deprecated-pkg",
					url: null,
					description: null,
				},
			];

			expect(mockScanResult).toHaveLength(2);
			expect(mockScanResult[0]?.level).toBe("fatal");
			expect(mockScanResult[1]?.level).toBe("warn");
			expect(mockScanResult[1]?.url).toBeNull();
		});
	});

	describe("Runtime type checking", () => {
		test("should handle type guards for FatalSeverity", () => {
			function isFatalSeverity(value: unknown): value is FatalSeverity {
				return (
					typeof value === "string" &&
					(value === "CRITICAL" || value === "HIGH")
				);
			}

			expect(isFatalSeverity("CRITICAL")).toBe(true);
			expect(isFatalSeverity("HIGH")).toBe(true);
			expect(isFatalSeverity("MEDIUM")).toBe(false);
			expect(isFatalSeverity("")).toBe(false);
			expect(isFatalSeverity(null)).toBe(false);
			expect(isFatalSeverity(undefined)).toBe(false);
			expect(isFatalSeverity(123)).toBe(false);
			expect(isFatalSeverity({})).toBe(false);
		});

		test("should handle advisory level validation", () => {
			function isValidAdvisoryLevel(level: unknown): level is "fatal" | "warn" {
				return level === "fatal" || level === "warn";
			}

			expect(isValidAdvisoryLevel("fatal")).toBe(true);
			expect(isValidAdvisoryLevel("warn")).toBe(true);
			expect(isValidAdvisoryLevel("error")).toBe(false);
			expect(isValidAdvisoryLevel("info")).toBe(false);
			expect(isValidAdvisoryLevel(null)).toBe(false);
		});

		test("should handle package validation", () => {
			function isValidPackage(pkg: unknown): pkg is Bun.Security.Package {
				if (typeof pkg !== "object" || pkg === null) return false;
				const p = pkg as Record<string, unknown>;
				return (
					typeof p.name === "string" &&
					typeof p.version === "string" &&
					typeof p.requestedRange === "string" &&
					typeof p.tarball === "string"
				);
			}

			const validPackage = {
				name: "test",
				version: "1.0.0",
				requestedRange: "^1.0.0",
				tarball: "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
			};

			const invalidPackage = {
				name: "test",
				version: 123, // Wrong type
			};

			expect(isValidPackage(validPackage)).toBe(true);
			expect(isValidPackage(invalidPackage)).toBe(false);
			expect(isValidPackage(null)).toBe(false);
			expect(isValidPackage("string")).toBe(false);
		});
	});

	describe("Generic type operations", () => {
		test("should work with array operations", () => {
			const severities: FatalSeverity[] = ["CRITICAL", "HIGH"];

			const mapped = severities.map((s) => s.toLowerCase());
			expect(mapped).toEqual(["critical", "high"]);

			const filtered = severities.filter((s) => s === "CRITICAL");
			expect(filtered).toEqual(["CRITICAL"]);

			const found = severities.find((s) => s.includes("HIGH"));
			expect(found).toBe("HIGH");
		});

		test("should work with Set operations", () => {
			const severitySet = new Set<FatalSeverity>([
				"CRITICAL",
				"HIGH",
				"CRITICAL",
			]);
			expect(severitySet.size).toBe(2);
			expect(severitySet.has("CRITICAL")).toBe(true);
			expect(severitySet.has("HIGH")).toBe(true);
		});

		test("should work with Map operations", () => {
			const severityMap = new Map<FatalSeverity, number>();
			severityMap.set("CRITICAL", 10);
			severityMap.set("HIGH", 7);

			expect(severityMap.get("CRITICAL")).toBe(10);
			expect(severityMap.get("HIGH")).toBe(7);
			expect(severityMap.size).toBe(2);
		});
	});

	describe("Union type handling", () => {
		test("should handle advisory level union correctly", () => {
			type AdvisoryLevel = "fatal" | "warn";

			function processLevel(level: AdvisoryLevel): string {
				switch (level) {
					case "fatal":
						return "Block installation";
					case "warn":
						return "Show warning";
					default: {
						// TypeScript should know this is never reached
						const exhaustive: never = level;
						return exhaustive;
					}
				}
			}

			expect(processLevel("fatal")).toBe("Block installation");
			expect(processLevel("warn")).toBe("Show warning");
		});

		test("should handle nullable types correctly", () => {
			function processDescription(description: string | null): string {
				if (description === null) {
					return "No description available";
				}
				return description.trim();
			}

			expect(processDescription("  Test description  ")).toBe(
				"Test description",
			);
			expect(processDescription(null)).toBe("No description available");
		});
	});
});
