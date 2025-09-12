/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll } from "bun:test";
import { VulnerabilityProcessor } from "../processor.js";
import type { OSVVulnerability } from "../schema.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("VulnerabilityProcessor", () => {
	const processor = new VulnerabilityProcessor();

	describe("basic processing", () => {
		test("should return empty array for no vulnerabilities", () => {
			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities([], packages);
			expect(result).toEqual([]);
		});

		test("should return empty array for no packages", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test vulnerability",
					affected: [],
				},
			];

			const result = processor.processVulnerabilities(vulns, []);
			expect(result).toEqual([]);
		});

		test("should return empty array for vulnerability with no affected packages", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test vulnerability",
					// no affected field
				},
			];

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);
			expect(result).toEqual([]);
		});
	});

	describe("vulnerability matching", () => {
		test("should match vulnerability to affected package", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test vulnerability",
					affected: [
						{
							package: {
								name: "vulnerable-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "vulnerable-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
				{
					name: "safe-package",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result).toHaveLength(1);
			expect(result[0]).toMatchObject({
				package: "vulnerable-package",
				level: expect.any(String),
				description: "Test vulnerability",
			});
		});

		test("should not match vulnerability to non-affected package", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test vulnerability",
					affected: [
						{
							package: {
								name: "different-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "safe-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);
			expect(result).toEqual([]);
		});

		test("should prevent duplicate advisories for same vulnerability+package", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test vulnerability",
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			// Should only create one advisory despite multiple affected entries
			expect(result).toHaveLength(1);
		});
	});

	describe("advisory creation", () => {
		test("should create advisory with correct structure", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "GHSA-test-1234",
					summary: "Critical security issue",
					database_specific: {
						severity: "CRITICAL",
					},
					references: [
						{
							type: "ADVISORY",
							url: "https://github.com/advisories/GHSA-test-1234",
						},
					],
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]).toMatchObject({
				level: "fatal", // CRITICAL severity should map to fatal
				package: "test-package",
				url: "https://github.com/advisories/GHSA-test-1234",
				description: "Critical security issue",
			});
		});

		test("should handle vulnerability without summary", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					details: "Detailed explanation of the vulnerability issue.",
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.description).toBe(
				"Detailed explanation of the vulnerability issue.",
			);
		});

		test("should truncate long descriptions", () => {
			const longDetails = "a".repeat(250); // Longer than MAX_DESCRIPTION_LENGTH

			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					details: longDetails,
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.description).toHaveLength(200); // 197 chars + "..."
			expect(result[0]?.description).toEndWith("...");
		});

		test("should handle vulnerability without description", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.description).toBeNull();
		});
	});

	describe("URL selection", () => {
		test("should prioritize advisory URLs", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test",
					references: [
						{ type: "WEB", url: "https://example.com/blog" },
						{
							type: "ADVISORY",
							url: "https://github.com/advisories/GHSA-test",
						},
						{ type: "REPORT", url: "https://bugtracker.com/123" },
					],
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.url).toBe("https://github.com/advisories/GHSA-test");
		});

		test("should fall back to CVE URLs when no advisory", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test",
					references: [
						{ type: "WEB", url: "https://example.com/blog" },
						{
							type: "REPORT",
							url: "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
						},
					],
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.url).toBe(
				"https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
			);
		});

		test("should use first reference as fallback", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test",
					references: [
						{ type: "WEB", url: "https://example.com/first" },
						{ type: "WEB", url: "https://example.com/second" },
					],
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.url).toBe("https://example.com/first");
		});

		test("should handle no references", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "Test",
					affected: [
						{
							package: {
								name: "test-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result[0]?.url).toBeNull();
		});
	});

	describe("multiple vulnerabilities and packages", () => {
		test("should process multiple vulnerabilities affecting multiple packages", () => {
			const vulns: OSVVulnerability[] = [
				{
					id: "TEST-001",
					summary: "First vulnerability",
					affected: [
						{
							package: {
								name: "package-a",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
				},
				{
					id: "TEST-002",
					summary: "Second vulnerability",
					affected: [
						{
							package: {
								name: "package-b",
								ecosystem: "npm",
							},
							versions: ["2.0.0"],
						},
					],
				},
			];

			const packages = [
				{
					name: "package-a",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
				{
					name: "package-b",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball: "test",
				},
			];

			const result = processor.processVulnerabilities(vulns, packages);

			expect(result).toHaveLength(2);
			expect(result.map((r) => r.package)).toContain("package-a");
			expect(result.map((r) => r.package)).toContain("package-b");
		});
	});
});
