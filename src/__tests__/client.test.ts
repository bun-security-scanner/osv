/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll, mock, afterEach } from "bun:test";
import { OSVClient } from "../client.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

const mockFetch = mock(() => Promise.resolve({} as Response));
const originalFetch = global.fetch;

afterEach(() => {
	mockFetch.mockClear();
	global.fetch = originalFetch as typeof fetch;
});

describe("OSVClient", () => {
	describe("package deduplication", () => {
		test("should deduplicate packages by name@version", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => ({ results: [] }),
			} as unknown as Response);

			const packages = [
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "test1",
				},
				{
					name: "lodash",
					version: "4.17.21",
					requestedRange: "^4.0.0",
					tarball: "test2",
				}, // duplicate
				{
					name: "express",
					version: "4.18.0",
					requestedRange: "^4.0.0",
					tarball: "test3",
				},
			];

			await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledTimes(1);
			const callArgs = mockFetch.mock.calls[0] as unknown as [
				string,
				{ body: string },
			];
			const body = JSON.parse(callArgs?.[1]?.body);
			expect(body.queries).toHaveLength(2);
		});

		test("should handle empty package list", async () => {
			const client = new OSVClient();
			const result = await client.queryVulnerabilities([]);
			expect(result).toEqual([]);
		});
	});

	describe("API strategy selection", () => {
		test("should use batch API for multiple packages when enabled", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => ({ results: [{ vulns: [] }, { vulns: [] }] }),
			} as unknown as Response);

			const packages = [
				{
					name: "package1",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
				{
					name: "package2",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball: "test",
				},
			];

			await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledWith(
				expect.stringContaining("/querybatch"),
				expect.objectContaining({ method: "POST" }),
			);
		});

		test("should use individual queries for single package", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => ({ vulns: [] }),
			} as unknown as Response);

			const packages = [
				{
					name: "single-package",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledWith(
				expect.stringContaining("/query"),
				expect.objectContaining({ method: "POST" }),
			);
		});

		test("should use individual queries when batch is disabled", async () => {
			process.env.OSV_DISABLE_BATCH = "true";
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => ({ vulns: [] }),
			} as unknown as Response);

			const packages = [
				{
					name: "package1",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
				{
					name: "package2",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball: "test",
				},
			];

			await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledWith(
				expect.stringContaining("/query"),
				expect.objectContaining({ method: "POST" }),
			);

			delete process.env.OSV_DISABLE_BATCH;
		});
	});

	describe("error handling", () => {
		test("should handle network errors gracefully", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockRejectedValue(
				new Error("Network error"),
			);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = await client.queryVulnerabilities(packages);
			expect(result).toEqual([]);
		});

		test("should handle HTTP errors gracefully", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: false,
				status: 500,
				statusText: "Internal Server Error",
			} as unknown as Response);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = await client.queryVulnerabilities(packages);
			expect(result).toEqual([]);
		});

		test("should handle malformed JSON responses", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => {
					throw new Error("Invalid JSON");
				},
			} as unknown as Response);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = await client.queryVulnerabilities(packages);
			expect(result).toEqual([]);
		});
	});

	describe("pagination support", () => {
		test("should handle paginated individual query responses", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch
				.mockResolvedValueOnce({
					ok: true,
					json: async () => ({
						vulns: [{ id: "vuln1", summary: "Test vuln 1" }],
						next_page_token: "page2",
					}),
				} as Response)
				.mockResolvedValueOnce({
					ok: true,
					json: async () => ({
						vulns: [{ id: "vuln2", summary: "Test vuln 2" }],
					}),
				} as unknown as Response);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			const result = await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledTimes(2);
			expect(result).toHaveLength(2);
		});
	});

	describe("batch query with vulnerability details", () => {
		test("should fetch vulnerability details after batch query", async () => {
			const client = new OSVClient();

			// Mock batch query response
			(global as { fetch: unknown }).fetch = mockFetch
				.mockResolvedValueOnce({
					ok: true,
					json: async () => ({
						results: [
							{
								vulns: [
									{ id: "GHSA-test-1", modified: "2023-01-01" },
									{ id: "GHSA-test-2", modified: "2023-01-02" },
								],
							},
							{
								vulns: [],
							},
						],
					}),
				} as Response)
				// Mock vulnerability detail responses
				.mockResolvedValue({
					ok: true,
					json: async () => ({
						id: "GHSA-test-1",
						summary: "Test vulnerability 1",
						affected: [],
					}),
				} as unknown as Response);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
				{
					name: "another-test",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball: "test2",
				},
			];

			const result = await client.queryVulnerabilities(packages);

			// Should call batch endpoint + detail endpoints for each unique vulnerability
			expect(mockFetch).toHaveBeenCalledTimes(3); // 1 batch + 2 details
			expect(result.length).toBeGreaterThanOrEqual(1);
		});

		test("should handle failed vulnerability detail fetches gracefully", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch
				.mockResolvedValueOnce({
					ok: true,
					json: async () => ({
						results: [
							{
								vulns: [{ id: "GHSA-test-1", modified: "2023-01-01" }],
							},
							{
								vulns: [],
							},
						],
					}),
				} as Response)
				// Mock failed detail fetch
				.mockResolvedValueOnce({
					ok: false,
					status: 404,
					statusText: "Not Found",
				} as unknown as Response);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
				{
					name: "another-test",
					version: "2.0.0",
					requestedRange: "2.0.0",
					tarball: "test2",
				},
			];

			const result = await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledTimes(2);
			expect(result).toEqual([]);
		});
	});

	describe("configuration", () => {
		test("should respect custom configuration", () => {
			const originalEnv = { ...process.env };

			process.env.OSV_API_BASE_URL = "https://custom-osv.dev/v1";
			process.env.OSV_TIMEOUT_MS = "60000";
			process.env.OSV_DISABLE_BATCH = "true";

			const client = new OSVClient();
			expect(client).toBeDefined();

			// Restore original env
			process.env = originalEnv;
		});
	});

	describe("request headers and format", () => {
		test("should include correct headers in requests", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => ({ vulns: [] }),
			} as unknown as Response);

			const packages = [
				{
					name: "test",
					version: "1.0.0",
					requestedRange: "1.0.0",
					tarball: "test",
				},
			];

			await client.queryVulnerabilities(packages);

			expect(mockFetch).toHaveBeenCalledWith(
				expect.any(String),
				expect.objectContaining({
					method: "POST",
					headers: expect.objectContaining({
						"Content-Type": "application/json",
						"User-Agent": "bun-osv-scanner/1.0.0",
					}),
				}),
			);
		});

		test("should format query payload correctly", async () => {
			const client = new OSVClient();

			(global as { fetch: unknown }).fetch = mockFetch.mockResolvedValue({
				ok: true,
				json: async () => ({ vulns: [] }),
			} as unknown as Response);

			const packages = [
				{
					name: "test-package",
					version: "1.2.3",
					requestedRange: "^1.0.0",
					tarball: "test",
				},
			];

			await client.queryVulnerabilities(packages);

			const callArgs = mockFetch.mock.calls[0] as unknown as [
				string,
				{ body: string },
			];
			const body = JSON.parse(callArgs?.[1]?.body);

			expect(body).toEqual({
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
				version: "1.2.3",
			});
		});
	});
});
