/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll, mock } from "bun:test";
import { scanner } from "../index.js";
import { OSVClient } from "../client.js";
import { VulnerabilityProcessor } from "../processor.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("OSV Scanner", () => {
	describe("scanner interface", () => {
		test("should have correct version", () => {
			expect(scanner.version).toBe("1");
		});

		test("should have scan method", () => {
			expect(typeof scanner.scan).toBe("function");
		});

		test("should implement Bun.Security.Scanner interface", () => {
			expect(scanner).toMatchObject({
				version: expect.any(String),
				scan: expect.any(Function),
			});
		});
	});

	describe("error handling", () => {
		test("should return empty array on scanner errors (fail-safe)", async () => {
			// Mock OSVClient to throw an error
			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			OSVClient.prototype.queryVulnerabilities = mock().mockRejectedValue(
				new Error("Network error"),
			);

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
				},
			];

			const result = await scanner.scan({ packages });

			// Should fail-safe and return empty array
			expect(result).toEqual([]);

			// Restore original method
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
		});

		test("should handle processor errors gracefully", async () => {
			// Mock successful client but failing processor
			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			const originalProcessVulnerabilities =
				VulnerabilityProcessor.prototype.processVulnerabilities;

			OSVClient.prototype.queryVulnerabilities = mock().mockResolvedValue([
				{
					id: "TEST-001",
					summary: "Test vulnerability",
				},
			]);

			VulnerabilityProcessor.prototype.processVulnerabilities =
				mock().mockImplementation(() => {
					throw new Error("Processor error");
				});

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
				},
			];

			const result = await scanner.scan({ packages });

			// Should fail-safe and return empty array
			expect(result).toEqual([]);

			// Restore original methods
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
			VulnerabilityProcessor.prototype.processVulnerabilities =
				originalProcessVulnerabilities;
		});
	});

	describe("successful scanning", () => {
		test("should return empty array for empty package list", async () => {
			const result = await scanner.scan({ packages: [] });
			expect(result).toEqual([]);
		});

		test("should integrate client and processor correctly", async () => {
			// Mock successful flow
			const mockVulns = [
				{
					id: "GHSA-test-1234",
					summary: "Test vulnerability",
					database_specific: {
						severity: "HIGH",
					},
					affected: [
						{
							package: {
								name: "vulnerable-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
					references: [
						{
							type: "ADVISORY",
							url: "https://github.com/advisories/GHSA-test-1234",
						},
					],
				},
			];

			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			OSVClient.prototype.queryVulnerabilities =
				mock().mockResolvedValue(mockVulns);

			const packages = [
				{
					name: "vulnerable-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/vulnerable-package/-/vulnerable-package-1.0.0.tgz",
				},
			];

			const result = await scanner.scan({ packages });

			expect(result).toHaveLength(1);
			expect(result[0]).toMatchObject({
				level: "fatal",
				package: "vulnerable-package",
				url: "https://github.com/advisories/GHSA-test-1234",
				description: "Test vulnerability",
			});

			// Restore original method
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
		});

		test("should handle no vulnerabilities found", async () => {
			// Mock client returning no vulnerabilities
			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			OSVClient.prototype.queryVulnerabilities = mock().mockResolvedValue([]);

			const packages = [
				{
					name: "safe-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz",
				},
			];

			const result = await scanner.scan({ packages });

			expect(result).toEqual([]);

			// Restore original method
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
		});

		test("should handle multiple packages with mixed results", async () => {
			const mockVulns = [
				{
					id: "GHSA-vuln-1",
					summary: "First vulnerability",
					database_specific: {
						severity: "CRITICAL",
					},
					affected: [
						{
							package: {
								name: "vulnerable-package",
								ecosystem: "npm",
							},
							versions: ["1.0.0"],
						},
					],
					references: [
						{
							type: "ADVISORY",
							url: "https://github.com/advisories/GHSA-vuln-1",
						},
					],
				},
			];

			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			OSVClient.prototype.queryVulnerabilities =
				mock().mockResolvedValue(mockVulns);

			const packages = [
				{
					name: "vulnerable-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/vulnerable-package/-/vulnerable-package-1.0.0.tgz",
				},
				{
					name: "safe-package",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball:
						"https://registry.npmjs.org/safe-package/-/safe-package-2.0.0.tgz",
				},
			];

			const result = await scanner.scan({ packages });

			// Should only find advisory for vulnerable package
			expect(result).toHaveLength(1);
			expect(result[0]?.package).toBe("vulnerable-package");

			// Restore original method
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
		});
	});

	describe("logging", () => {
		test("should log scan start and completion", async () => {
			// Mock successful but empty scan
			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			OSVClient.prototype.queryVulnerabilities = mock().mockResolvedValue([]);

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
				},
			];

			await scanner.scan({ packages });

			// Verify scan was attempted (no easy way to test logs without mocking console)
			expect(OSVClient.prototype.queryVulnerabilities).toHaveBeenCalledWith(
				packages,
			);

			// Restore original method
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
		});
	});

	describe("component integration", () => {
		test("should pass packages correctly to client", async () => {
			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			const mockQuery = mock().mockResolvedValue([]);
			OSVClient.prototype.queryVulnerabilities = mockQuery;

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "^1.0.0",
					tarball:
						"https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
				},
			];

			await scanner.scan({ packages });

			expect(mockQuery).toHaveBeenCalledTimes(1);
			expect(mockQuery).toHaveBeenCalledWith(packages);

			// Restore original method
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
		});

		test("should pass vulnerabilities and packages correctly to processor", async () => {
			const mockVulns = [
				{
					id: "TEST-001",
					summary: "Test vulnerability",
				},
			];

			const originalQueryVulnerabilities =
				OSVClient.prototype.queryVulnerabilities;
			const originalProcessVulnerabilities =
				VulnerabilityProcessor.prototype.processVulnerabilities;

			OSVClient.prototype.queryVulnerabilities =
				mock().mockResolvedValue(mockVulns);
			const mockProcess = mock().mockReturnValue([]);
			VulnerabilityProcessor.prototype.processVulnerabilities = mockProcess;

			const packages = [
				{
					name: "test-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball:
						"https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
				},
			];

			await scanner.scan({ packages });

			expect(mockProcess).toHaveBeenCalledTimes(1);
			expect(mockProcess).toHaveBeenCalledWith(mockVulns, packages);

			// Restore original methods
			OSVClient.prototype.queryVulnerabilities = originalQueryVulnerabilities;
			VulnerabilityProcessor.prototype.processVulnerabilities =
				originalProcessVulnerabilities;
		});
	});
});
