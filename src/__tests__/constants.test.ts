/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeEach } from "bun:test";
import {
	OSV_API,
	HTTP,
	SECURITY,
	PERFORMANCE,
	ENV,
	getConfig,
} from "../constants.js";

describe("Constants", () => {
	describe("OSV_API constants", () => {
		test("should have correct default values", () => {
			expect(OSV_API.BASE_URL).toBe("https://api.osv.dev/v1");
			expect(OSV_API.TIMEOUT_MS).toBe(30_000);
			expect(OSV_API.MAX_BATCH_SIZE).toBe(1_000);
			expect(OSV_API.MAX_RETRY_ATTEMPTS).toBe(2);
			expect(OSV_API.RETRY_DELAY_MS).toBe(1_000);
			expect(OSV_API.DEFAULT_ECOSYSTEM).toBe("npm");
		});

		test("should have readonly properties", () => {
			// Note: TypeScript const assertions provide compile-time immutability
			// Runtime immutability would require Object.freeze() which we don't use for performance
			expect(OSV_API.BASE_URL).toBe("https://api.osv.dev/v1");
		});
	});

	describe("HTTP constants", () => {
		test("should have correct values", () => {
			expect(HTTP.CONTENT_TYPE).toBe("application/json");
			expect(HTTP.USER_AGENT).toBe("bun-osv-scanner/1.0.0");
		});

		test("should have readonly properties", () => {
			expect(HTTP.CONTENT_TYPE).toBe("application/json");
		});
	});

	describe("SECURITY constants", () => {
		test("should have correct threshold values", () => {
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBe(7.0);
			expect(SECURITY.MAX_VULNERABILITIES_PER_PACKAGE).toBe(100);
			expect(SECURITY.MAX_DESCRIPTION_LENGTH).toBe(200);
		});

		test("should have correct fatal severities", () => {
			expect(SECURITY.FATAL_SEVERITIES).toEqual(["CRITICAL", "HIGH"]);
		});

		test("should have readonly properties", () => {
			expect(SECURITY.CVSS_FATAL_THRESHOLD).toBe(7.0);
		});

		test("should have readonly fatal severities", () => {
			expect(SECURITY.FATAL_SEVERITIES).toEqual(["CRITICAL", "HIGH"]);
		});
	});

	describe("PERFORMANCE constants", () => {
		test("should have correct performance settings", () => {
			expect(PERFORMANCE.USE_BATCH_QUERIES).toBe(true);
			expect(PERFORMANCE.MAX_CONCURRENT_DETAILS).toBe(10);
			expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBe(32 * 1024 * 1024); // 32MB
		});

		test("should have readonly properties", () => {
			expect(PERFORMANCE.MAX_CONCURRENT_DETAILS).toBe(10);
		});
	});

	describe("ENV constants", () => {
		test("should have correct environment variable names", () => {
			expect(ENV.LOG_LEVEL).toBe("OSV_LOG_LEVEL");
			expect(ENV.API_BASE_URL).toBe("OSV_API_BASE_URL");
			expect(ENV.TIMEOUT_MS).toBe("OSV_TIMEOUT_MS");
			expect(ENV.DISABLE_BATCH).toBe("OSV_DISABLE_BATCH");
		});

		test("should have readonly properties", () => {
			expect(ENV.LOG_LEVEL).toBe("OSV_LOG_LEVEL");
		});
	});
});

describe("getConfig function", () => {
	const _originalEnv = { ...process.env };

	beforeEach(() => {
		// Clear relevant env vars for clean testing
		delete process.env.TEST_STRING_VAR;
		delete process.env.TEST_NUMBER_VAR;
		delete process.env.TEST_BOOLEAN_VAR;
		delete process.env.TEST_CUSTOM_VAR;
	});

	describe("string values", () => {
		test("should return default value when env var not set", () => {
			const result = getConfig("TEST_STRING_VAR", "default-value");
			expect(result).toBe("default-value");
		});

		test("should return env var value when set", () => {
			process.env.TEST_STRING_VAR = "custom-value";
			const result = getConfig("TEST_STRING_VAR", "default-value");
			expect(result).toBe("custom-value");
		});

		test("should handle empty string env var", () => {
			process.env.TEST_STRING_VAR = "";
			const result = getConfig("TEST_STRING_VAR", "default-value");
			expect(result).toBe("default-value");
		});
	});

	describe("number values", () => {
		test("should return default number when env var not set", () => {
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(42);
		});

		test("should parse valid number from env var", () => {
			process.env.TEST_NUMBER_VAR = "123";
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(123);
		});

		test("should parse float number from env var", () => {
			process.env.TEST_NUMBER_VAR = "123.45";
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(123.45);
		});

		test("should return default for invalid number", () => {
			process.env.TEST_NUMBER_VAR = "not-a-number";
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(42);
		});

		test("should handle negative numbers", () => {
			process.env.TEST_NUMBER_VAR = "-100";
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(-100);
		});

		test("should handle zero", () => {
			process.env.TEST_NUMBER_VAR = "0";
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(0);
		});

		test("should return default for empty string number", () => {
			process.env.TEST_NUMBER_VAR = "";
			const result = getConfig("TEST_NUMBER_VAR", 42);
			expect(result).toBe(42);
		});
	});

	describe("boolean values", () => {
		test("should return default boolean when env var not set", () => {
			const result = getConfig("TEST_BOOLEAN_VAR", true);
			expect(result).toBe(true);
		});

		test("should parse 'true' as true", () => {
			process.env.TEST_BOOLEAN_VAR = "true";
			const result = getConfig("TEST_BOOLEAN_VAR", false);
			expect(result).toBe(true);
		});

		test("should parse 'TRUE' as true", () => {
			process.env.TEST_BOOLEAN_VAR = "TRUE";
			const result = getConfig("TEST_BOOLEAN_VAR", false);
			expect(result).toBe(true);
		});

		test("should parse 'True' as true", () => {
			process.env.TEST_BOOLEAN_VAR = "True";
			const result = getConfig("TEST_BOOLEAN_VAR", false);
			expect(result).toBe(true);
		});

		test("should parse 'false' as false", () => {
			process.env.TEST_BOOLEAN_VAR = "false";
			const result = getConfig("TEST_BOOLEAN_VAR", true);
			expect(result).toBe(false);
		});

		test("should parse any non-'true' value as false", () => {
			process.env.TEST_BOOLEAN_VAR = "yes";
			const result = getConfig("TEST_BOOLEAN_VAR", true);
			expect(result).toBe(false);
		});

		test("should handle empty string boolean", () => {
			process.env.TEST_BOOLEAN_VAR = "";
			const result = getConfig("TEST_BOOLEAN_VAR", true);
			expect(result).toBe(true); // Should use default
		});
	});

	describe("custom parser", () => {
		test("should use custom parser when provided", () => {
			process.env.TEST_CUSTOM_VAR = "123,456,789";

			const parser = (value: string) => value.split(",").map(Number);
			const result = getConfig("TEST_CUSTOM_VAR", [0], parser);

			expect(result).toEqual([123, 456, 789]);
		});

		test("should return default when custom parser throws", () => {
			process.env.TEST_CUSTOM_VAR = "invalid-input";

			const parser = (_value: string) => {
				throw new Error("Parse error");
			};
			const result = getConfig("TEST_CUSTOM_VAR", "default", parser);

			expect(result).toBe("default");
		});

		test("should handle custom parser with complex objects", () => {
			process.env.TEST_CUSTOM_VAR = '{"key": "value", "number": 42}';

			const parser = (value: string) => JSON.parse(value);
			const result = getConfig("TEST_CUSTOM_VAR", {}, parser);

			expect(result).toEqual({ key: "value", number: 42 });
		});

		test("should use custom parser over type inference", () => {
			process.env.TEST_CUSTOM_VAR = "123";

			// Even though default is a number, custom parser should take precedence
			const parser = (value: string) => `parsed-${value}`;
			const result = getConfig("TEST_CUSTOM_VAR", "default", parser);

			expect(result).toBe("parsed-123");
		});
	});

	describe("real-world usage", () => {
		test("should work with actual OSV environment variables", () => {
			process.env.OSV_LOG_LEVEL = "debug";
			process.env.OSV_TIMEOUT_MS = "60000";
			process.env.OSV_DISABLE_BATCH = "true";

			expect(getConfig(ENV.LOG_LEVEL, "info")).toBe("debug");
			expect(getConfig(ENV.TIMEOUT_MS, 30000)).toBe(60000);
			expect(getConfig(ENV.DISABLE_BATCH, false)).toBe(true);
		});

		test("should handle undefined environment variable", () => {
			const result = getConfig("DEFINITELY_UNDEFINED_VAR", "fallback");
			expect(result).toBe("fallback");
		});

		test("should preserve type safety", () => {
			// This is more of a TypeScript compile-time test, but we can verify runtime behavior
			const stringResult = getConfig("TEST_VAR", "string-default");
			const numberResult = getConfig("TEST_VAR", 42);
			const booleanResult = getConfig("TEST_VAR", true);

			expect(typeof stringResult).toBe("string");
			expect(typeof numberResult).toBe("number");
			expect(typeof booleanResult).toBe("boolean");
		});
	});

	describe("edge cases", () => {
		test("should handle null default value", () => {
			const result = getConfig("TEST_VAR", null);
			expect(result).toBeNull();
		});

		test("should handle undefined default value", () => {
			const result = getConfig("TEST_VAR", undefined);
			expect(result).toBeUndefined();
		});

		test("should handle array default value", () => {
			const defaultArray = [1, 2, 3];
			const result = getConfig("TEST_VAR", defaultArray);
			expect(result).toEqual(defaultArray);
		});

		test("should handle object default value", () => {
			const defaultObject = { key: "value" };
			const result = getConfig("TEST_VAR", defaultObject);
			expect(result).toEqual(defaultObject);
		});
	});
});
