/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll } from "bun:test";
import { isPackageAffected } from "../semver.js";
import type { OSVAffected } from "../schema.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("isPackageAffected", () => {
	const testPackage = {
		name: "test-package",
		version: "1.5.0",
		requestedRange: "^1.0.0",
		tarball: "https://registry.npmjs.org/test-package/-/test-package-1.5.0.tgz",
	};

	describe("package name matching", () => {
		test("should return false for different package name", () => {
			const affected: OSVAffected = {
				package: {
					name: "different-package",
					ecosystem: "npm",
				},
				versions: ["1.5.0"],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});

		test("should match correct package name", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				versions: ["1.5.0"],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(true);
		});
	});

	describe("explicit versions list", () => {
		test("should match package version in explicit versions list", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				versions: ["1.0.0", "1.5.0", "2.0.0"],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(true);
		});

		test("should not match package version not in explicit versions list", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				versions: ["1.0.0", "1.4.0", "2.0.0"],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});

		test("should handle empty versions list", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				versions: [],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});
	});

	describe("SEMVER ranges", () => {
		test("should match version in introduced range", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(true);
		});

		test("should not match version before introduced range", () => {
			const pkg = { ...testPackage, version: "0.9.0" };

			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }],
					},
				],
			};

			const result = isPackageAffected(pkg, affected);
			expect(result).toBe(false);
		});

		test("should not match version after fixed range", () => {
			const pkg = { ...testPackage, version: "2.0.0" };

			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }, { fixed: "1.8.0" }],
					},
				],
			};

			const result = isPackageAffected(pkg, affected);
			expect(result).toBe(false);
		});

		test("should match version in vulnerable range", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }, { fixed: "1.8.0" }],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected); // version 1.5.0
			expect(result).toBe(true);
		});

		test("should handle last_affected event", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }, { last_affected: "1.6.0" }],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected); // version 1.5.0
			expect(result).toBe(true);
		});

		test("should not match version after last_affected", () => {
			const pkg = { ...testPackage, version: "1.7.0" };

			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }, { last_affected: "1.6.0" }],
					},
				],
			};

			const result = isPackageAffected(pkg, affected);
			expect(result).toBe(false);
		});

		test("should handle introduced: '0' as wildcard", () => {
			const pkg = { ...testPackage, version: "0.1.0" };

			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "0" }, { fixed: "0.2.0" }],
					},
				],
			};

			const result = isPackageAffected(pkg, affected);
			expect(result).toBe(true);
		});

		test("should handle multiple range events", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [
							{ introduced: "1.0.0" },
							{ fixed: "1.3.0" },
							{ introduced: "1.4.0" },
							{ fixed: "1.7.0" },
						],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected); // version 1.5.0
			expect(result).toBe(true);
		});

		test("should handle invalid semver gracefully", () => {
			const pkg = { ...testPackage, version: "invalid-version" };

			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "1.0.0" }],
					},
				],
			};

			const result = isPackageAffected(pkg, affected);
			expect(result).toBe(false);
		});

		test("should handle empty events array", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});
	});

	describe("non-SEMVER ranges", () => {
		test("should return false for GIT range type", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "GIT",
						events: [{ introduced: "abc123" }],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});

		test("should return false for ECOSYSTEM range type", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "ECOSYSTEM",
						events: [{ introduced: "1.0.0" }],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});
	});

	describe("multiple ranges", () => {
		test("should match if any range matches", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [
							{ introduced: "2.0.0" }, // Doesn't match
						],
					},
					{
						type: "SEMVER",
						events: [
							{ introduced: "1.0.0" },
							{ fixed: "1.8.0" }, // Matches
						],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected); // version 1.5.0
			expect(result).toBe(true);
		});

		test("should not match if no ranges match", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "2.0.0" }],
					},
					{
						type: "GIT",
						events: [{ introduced: "abc123" }],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(false);
		});
	});

	describe("combined versions and ranges", () => {
		test("should match explicit versions even if ranges don't match", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				versions: ["1.5.0"],
				ranges: [
					{
						type: "SEMVER",
						events: [
							{ introduced: "2.0.0" }, // Doesn't match
						],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(true);
		});

		test("should match ranges even if explicit versions don't match", () => {
			const affected: OSVAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				versions: ["2.0.0"], // Doesn't match
				ranges: [
					{
						type: "SEMVER",
						events: [
							{ introduced: "1.0.0" },
							{ fixed: "1.8.0" }, // Matches
						],
					},
				],
			};

			const result = isPackageAffected(testPackage, affected);
			expect(result).toBe(true);
		});
	});
});
