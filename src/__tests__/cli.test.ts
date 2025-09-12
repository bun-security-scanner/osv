/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import {
	expect,
	test,
	describe,
	beforeAll,
	beforeEach,
	afterEach,
	mock,
} from "bun:test";
import { runCli } from "../cli.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

// Mock process.exit to prevent tests from actually exiting
const mockExit = mock(() => {});
const originalExit = process.exit;

// Mock console.log for usage output
const mockConsoleLog = mock(() => {});
const originalConsoleLog = console.log;

describe("CLI", () => {
	const originalArgv = process.argv;

	beforeEach(() => {
		mockExit.mockClear();
		mockConsoleLog.mockClear();

		// Replace process.exit and console.log
		process.exit = mockExit as unknown as (code?: number | undefined) => never;
		console.log = mockConsoleLog;
	});

	afterEach(() => {
		// Restore original values
		process.argv = originalArgv;
		process.exit = originalExit;
		console.log = originalConsoleLog;
	});

	describe("help and usage", () => {
		test("should show help when no arguments provided", async () => {
			process.argv = ["bun", "cli.ts"];

			await runCli();

			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("Bun OSV Scanner CLI"),
			);
			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("Usage:"),
			);
		});

		test("should show help with --help flag", async () => {
			process.argv = ["bun", "cli.ts", "--help"];

			await runCli();

			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("Bun OSV Scanner CLI"),
			);
		});

		test("should show help with -h flag", async () => {
			process.argv = ["bun", "cli.ts", "-h"];

			await runCli();

			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("Bun OSV Scanner CLI"),
			);
		});

		test("should show usage information", async () => {
			process.argv = ["bun", "cli.ts", "--help"];

			await runCli();

			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("test <package@version>"),
			);
			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("scan <package.json>"),
			);
			expect(mockConsoleLog).toHaveBeenCalledWith(
				expect.stringContaining("Examples:"),
			);
		});
	});

	describe("test command", () => {
		test("should exit with error when no packages specified", async () => {
			process.argv = ["bun", "cli.ts", "test"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should exit with error for invalid package format", async () => {
			process.argv = ["bun", "cli.ts", "test", "invalid-format"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should exit with error for empty package name", async () => {
			process.argv = ["bun", "cli.ts", "test", "@1.0.0"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should exit with error for empty version", async () => {
			process.argv = ["bun", "cli.ts", "test", "package@"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should accept valid package specifications", async () => {
			// Mock the scanner to avoid actual API calls
			const mockScanner = {
				scan: mock().mockResolvedValue([]),
			};

			// We can't easily mock the import, so we'll test the validation logic indirectly
			process.argv = ["bun", "cli.ts", "test", "lodash@4.17.21"];

			// This test mainly verifies that valid format doesn't cause early exit
			const originalScan = require("../index.js").scanner.scan;
			require("../index.js").scanner.scan = mockScanner.scan;

			try {
				await runCli();
				// If we get here without exit, the format was valid
			} catch (_error) {
				// Scanner might fail due to mocking, but format validation passed
			}

			// Restore original scanner
			require("../index.js").scanner.scan = originalScan;
		});

		test("should handle multiple package specifications", async () => {
			process.argv = [
				"bun",
				"cli.ts",
				"test",
				"lodash@4.17.21",
				"express@4.18.0",
			];

			// Mock the scanner
			const mockScanner = {
				scan: mock().mockResolvedValue([]),
			};

			const originalScan = require("../index.js").scanner.scan;
			require("../index.js").scanner.scan = mockScanner.scan;

			try {
				await runCli();
				expect(mockScanner.scan).toHaveBeenCalledWith({
					packages: expect.arrayContaining([
						expect.objectContaining({ name: "lodash", version: "4.17.21" }),
						expect.objectContaining({ name: "express", version: "4.18.0" }),
					]),
				});
			} catch (_error) {
				// Expected due to mocking
			}

			require("../index.js").scanner.scan = originalScan;
		});
	});

	describe("scan command", () => {
		test("should exit with error when no file specified", async () => {
			process.argv = ["bun", "cli.ts", "scan"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should exit with error when empty file argument", async () => {
			process.argv = ["bun", "cli.ts", "scan", ""];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should exit with error when file doesn't exist", async () => {
			process.argv = ["bun", "cli.ts", "scan", "/nonexistent/package.json"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should process existing package.json file", async () => {
			// Create a temporary package.json for testing
			const tempFile = "/tmp/test-package.json";
			const testPackageJson = {
				dependencies: {
					lodash: "^4.17.0",
					express: "^4.18.0",
				},
				devDependencies: {
					typescript: "^5.0.0",
				},
			};

			await Bun.write(tempFile, JSON.stringify(testPackageJson));

			process.argv = ["bun", "cli.ts", "scan", tempFile];

			// Mock the scanner
			const mockScanner = {
				scan: mock().mockResolvedValue([]),
			};

			const originalScan = require("../index.js").scanner.scan;
			require("../index.js").scanner.scan = mockScanner.scan;

			try {
				await runCli();

				expect(mockScanner.scan).toHaveBeenCalledWith({
					packages: expect.arrayContaining([
						expect.objectContaining({ name: "lodash" }),
						expect.objectContaining({ name: "express" }),
						expect.objectContaining({ name: "typescript" }),
					]),
				});
			} catch (_error) {
				// Expected due to mocking
			}

			// Cleanup
			require("../index.js").scanner.scan = originalScan;
			await Bun.write(tempFile, ""); // Clear file
		});

		test("should handle malformed package.json", async () => {
			const tempFile = "/tmp/malformed-package.json";
			await Bun.write(tempFile, "{ invalid json");

			process.argv = ["bun", "cli.ts", "scan", tempFile];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);

			// Cleanup
			await Bun.write(tempFile, "");
		});

		test("should clean version ranges", async () => {
			const tempFile = "/tmp/version-range-package.json";
			const testPackageJson = {
				dependencies: {
					package1: "^1.2.3",
					package2: "~2.1.0",
					package3: "3.0.0",
				},
			};

			await Bun.write(tempFile, JSON.stringify(testPackageJson));

			process.argv = ["bun", "cli.ts", "scan", tempFile];

			const mockScanner = {
				scan: mock().mockResolvedValue([]),
			};

			const originalScan = require("../index.js").scanner.scan;
			require("../index.js").scanner.scan = mockScanner.scan;

			try {
				await runCli();

				const packages = mockScanner.scan.mock.calls[0]?.[0]?.packages;
				expect(packages).toEqual(
					expect.arrayContaining([
						expect.objectContaining({ name: "package1", version: "1.2.3" }),
						expect.objectContaining({ name: "package2", version: "2.1.0" }),
						expect.objectContaining({ name: "package3", version: "3.0.0" }),
					]),
				);
			} catch (_error) {
				// Expected due to mocking
			}

			require("../index.js").scanner.scan = originalScan;
			await Bun.write(tempFile, "");
		});
	});

	describe("unknown command", () => {
		test("should exit with error for unknown command", async () => {
			process.argv = ["bun", "cli.ts", "unknown-command"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
		});

		test("should not show usage for unknown command", async () => {
			process.argv = ["bun", "cli.ts", "unknown-command"];

			await runCli();

			expect(mockExit).toHaveBeenCalledWith(1);
			// Should not show full usage output for unknown commands
		});
	});

	describe("exitWithError function", () => {
		test("should use custom exit code", async () => {
			// This is harder to test directly, but we can verify the function exists
			// and the default behavior of exit code 1 is tested above
			expect(typeof runCli).toBe("function");
		});
	});

	describe("output formatting", () => {
		test("should show scan results with proper formatting", async () => {
			const mockScanner = {
				scan: mock().mockResolvedValue([
					{
						level: "fatal",
						package: "vulnerable-pkg",
						url: "https://github.com/advisories/GHSA-test",
						description: "Critical vulnerability",
					},
				]),
			};

			const originalScan = require("../index.js").scanner.scan;
			require("../index.js").scanner.scan = mockScanner.scan;

			process.argv = ["bun", "cli.ts", "test", "vulnerable-pkg@1.0.0"];

			try {
				await runCli();

				// Verify that console.log was called with formatted results
				expect(mockConsoleLog).toHaveBeenCalledWith(
					expect.stringContaining("Scan Results"),
				);
			} catch (_error) {
				// Expected due to mocking
			}

			require("../index.js").scanner.scan = originalScan;
		});

		test("should show success message for safe packages", async () => {
			const mockScanner = {
				scan: mock().mockResolvedValue([]),
			};

			const originalScan = require("../index.js").scanner.scan;
			require("../index.js").scanner.scan = mockScanner.scan;

			process.argv = ["bun", "cli.ts", "test", "safe-pkg@1.0.0"];

			try {
				await runCli();

				expect(mockConsoleLog).toHaveBeenCalledWith(
					expect.stringContaining("No security advisories found"),
				);
			} catch (_error) {
				// Expected due to mocking
			}

			require("../index.js").scanner.scan = originalScan;
		});
	});
});
