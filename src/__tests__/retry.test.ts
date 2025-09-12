/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll } from "bun:test";
import { withRetry, DEFAULT_RETRY_CONFIG } from "../retry.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("withRetry", () => {
	describe("successful operations", () => {
		test("should return result on first attempt", async () => {
			const operation = async () => "success";

			const result = await withRetry(operation, "test operation");
			expect(result).toBe("success");
		});

		test("should return result on retry after initial failure", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				if (attempts === 1) {
					throw new Error("Temporary failure");
				}
				return "success after retry";
			};

			const result = await withRetry(operation, "test operation");
			expect(result).toBe("success after retry");
			expect(attempts).toBe(2);
		});
	});

	describe("retry logic", () => {
		test("should respect maxAttempts configuration", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				throw new Error("Always fails");
			};

			const config = { ...DEFAULT_RETRY_CONFIG, maxAttempts: 2 };

			await expect(withRetry(operation, "test", config)).rejects.toThrow(
				"Always fails",
			);
			expect(attempts).toBe(2);
		});

		test("should use exponential backoff delays", async () => {
			let attempts = 0;
			const startTime = Date.now();
			const delays: number[] = [];

			const operation = async () => {
				attempts++;
				if (attempts > 1) {
					delays.push(Date.now() - startTime);
				}
				if (attempts < 3) {
					throw new Error("Retryable error");
				}
				return "success";
			};

			const config = { maxAttempts: 3, delayMs: 10, shouldRetry: () => true };

			const result = await withRetry(operation, "test", config);
			expect(result).toBe("success");
			expect(attempts).toBe(3);

			// Verify exponential backoff (approximately)
			if (delays.length >= 2) {
				expect(delays[1]).toBeGreaterThan(delays[0] || 0);
			}
		});
	});

	describe("shouldRetry function", () => {
		test("should respect custom shouldRetry function", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				throw new Error("400 Bad Request");
			};

			const config = {
				maxAttempts: 3,
				delayMs: 1,
				shouldRetry: (error: Error) => !error.message.includes("400"),
			};

			await expect(withRetry(operation, "test", config)).rejects.toThrow(
				"400 Bad Request",
			);
			expect(attempts).toBe(1); // Should not retry on 400 error
		});

		test("should use default shouldRetry logic", async () => {
			let attempts = 0;

			// Test 400 error (should not retry)
			const operation400 = async () => {
				attempts++;
				throw new Error("HTTP 400: Bad Request");
			};

			await expect(withRetry(operation400, "test")).rejects.toThrow();
			expect(attempts).toBe(1);

			// Reset counter
			attempts = 0;

			// Test 500 error (should retry)
			const operation500 = async () => {
				attempts++;
				if (attempts < 2) {
					throw new Error("HTTP 500: Internal Server Error");
				}
				return "success";
			};

			const result = await withRetry(operation500, "test");
			expect(result).toBe("success");
			expect(attempts).toBe(2);
		});

		test("should not retry on 401 Unauthorized", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				throw new Error("HTTP 401: Unauthorized");
			};

			await expect(withRetry(operation, "test")).rejects.toThrow();
			expect(attempts).toBe(1);
		});

		test("should not retry on 403 Forbidden", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				throw new Error("HTTP 403: Forbidden");
			};

			await expect(withRetry(operation, "test")).rejects.toThrow();
			expect(attempts).toBe(1);
		});

		test("should not retry on 404 Not Found", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				throw new Error("HTTP 404: Not Found");
			};

			await expect(withRetry(operation, "test")).rejects.toThrow();
			expect(attempts).toBe(1);
		});

		test("should retry on 502 Bad Gateway", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				if (attempts < 2) {
					throw new Error("HTTP 502: Bad Gateway");
				}
				return "success";
			};

			const result = await withRetry(operation, "test");
			expect(result).toBe("success");
			expect(attempts).toBe(2);
		});

		test("should retry on network errors", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				if (attempts < 2) {
					throw new Error("Network error: ECONNRESET");
				}
				return "success";
			};

			const result = await withRetry(operation, "test");
			expect(result).toBe("success");
			expect(attempts).toBe(2);
		});
	});

	describe("error handling", () => {
		test("should throw last error when all retries exhausted", async () => {
			const operation = async () => {
				throw new Error("Final error");
			};

			await expect(withRetry(operation, "test")).rejects.toThrow("Final error");
		});

		test("should handle non-Error exceptions", async () => {
			const operation = async () => {
				throw "String error";
			};

			await expect(withRetry(operation, "test")).rejects.toThrow(
				"String error",
			);
		});

		test("should handle null/undefined exceptions", async () => {
			const operation = async () => {
				throw null;
			};

			await expect(withRetry(operation, "test")).rejects.toThrow("null");
		});

		test("should handle object exceptions", async () => {
			const operation = async () => {
				throw { message: "Object error", code: 123 };
			};

			await expect(withRetry(operation, "test")).rejects.toThrow(
				"[object Object]",
			);
		});
	});

	describe("configuration edge cases", () => {
		test("should handle maxAttempts of 1", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				throw new Error("Always fails");
			};

			const config = { maxAttempts: 1, delayMs: 1, shouldRetry: () => true };

			await expect(withRetry(operation, "test", config)).rejects.toThrow();
			expect(attempts).toBe(1);
		});

		test("should handle zero delay", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				if (attempts < 2) {
					throw new Error("Retry once");
				}
				return "success";
			};

			const config = { maxAttempts: 2, delayMs: 0, shouldRetry: () => true };

			const result = await withRetry(operation, "test", config);
			expect(result).toBe("success");
		});

		test("should handle missing shouldRetry function", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				if (attempts < 2) {
					throw new Error("Retry once");
				}
				return "success";
			};

			const config = { maxAttempts: 2, delayMs: 1 }; // No shouldRetry function

			const result = await withRetry(operation, "test", config);
			expect(result).toBe("success");
		});
	});

	describe("operation naming", () => {
		test("should accept operation name for logging", async () => {
			const operation = async () => "success";

			const result = await withRetry(operation, "named operation");
			expect(result).toBe("success");
		});

		test("should handle empty operation name", async () => {
			const operation = async () => "success";

			const result = await withRetry(operation, "");
			expect(result).toBe("success");
		});
	});

	describe("default retry config", () => {
		test("should have correct default values", () => {
			expect(DEFAULT_RETRY_CONFIG.maxAttempts).toBe(3); // MAX_RETRY_ATTEMPTS + 1
			expect(DEFAULT_RETRY_CONFIG.delayMs).toBe(1000); // RETRY_DELAY_MS
			expect(typeof DEFAULT_RETRY_CONFIG.shouldRetry).toBe("function");
		});

		test("should use default config when none provided", async () => {
			let attempts = 0;
			const operation = async () => {
				attempts++;
				if (attempts <= 2) {
					throw new Error("HTTP 500: Server Error");
				}
				return "success";
			};

			const result = await withRetry(operation, "test"); // No config provided
			expect(result).toBe("success");
			expect(attempts).toBe(3);
		});
	});
});
