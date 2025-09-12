/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { expect, test, describe, beforeAll } from "bun:test";
import {
	OSVQuerySchema,
	OSVAffectedSchema,
	OSVVulnerabilitySchema,
	OSVResponseSchema,
	OSVBatchQuerySchema,
	OSVBatchResponseSchema,
} from "../schema.js";

// Set log level to warn to reduce test output noise
beforeAll(() => {
	process.env.OSV_LOG_LEVEL = "warn";
});

describe("Schema Validation", () => {
	describe("OSVQuerySchema", () => {
		test("should validate complete query", () => {
			const validQuery = {
				commit: "abc123",
				version: "1.0.0",
				package: {
					name: "test-package",
					ecosystem: "npm",
					purl: "pkg:npm/test-package@1.0.0",
				},
				page_token: "page123",
			};

			const result = OSVQuerySchema.parse(validQuery);
			expect(result).toEqual(validQuery);
		});

		test("should validate minimal query", () => {
			const minimalQuery = {};
			const result = OSVQuerySchema.parse(minimalQuery);
			expect(result).toEqual({});
		});

		test("should validate query with only package", () => {
			const packageQuery = {
				package: {
					name: "lodash",
					ecosystem: "npm",
				},
				version: "4.17.21",
			};

			const result = OSVQuerySchema.parse(packageQuery);
			expect(result).toEqual(packageQuery);
		});

		test("should validate query with purl", () => {
			const purlQuery = {
				package: {
					name: "lodash",
					ecosystem: "npm",
					purl: "pkg:npm/lodash@4.17.21",
				},
			};

			const result = OSVQuerySchema.parse(purlQuery);
			expect(result).toEqual(purlQuery);
		});

		test("should reject invalid query structure", () => {
			const invalidQuery = {
				package: "invalid-string", // Should be object
			};

			expect(() => OSVQuerySchema.parse(invalidQuery)).toThrow();
		});
	});

	describe("OSVAffectedSchema", () => {
		test("should validate complete affected package", () => {
			const validAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
					purl: "pkg:npm/test-package",
				},
				ranges: [
					{
						type: "SEMVER",
						repo: "https://github.com/test/test-package",
						events: [
							{
								introduced: "1.0.0",
								fixed: "1.2.0",
								last_affected: "1.1.9",
							},
						],
					},
				],
				versions: ["1.0.1", "1.0.2", "1.1.0"],
				ecosystem_specific: {
					severity: "HIGH",
				},
				database_specific: {
					source: "test-db",
				},
			};

			const result = OSVAffectedSchema.parse(validAffected);
			expect(result).toEqual(validAffected);
		});

		test("should validate minimal affected package", () => {
			const minimalAffected = {
				package: {
					name: "test-package",
					ecosystem: "npm",
				},
			};

			const result = OSVAffectedSchema.parse(minimalAffected);
			expect(result).toEqual(minimalAffected);
		});

		test("should validate affected with versions only", () => {
			const versionsAffected = {
				package: {
					name: "vulnerable-pkg",
					ecosystem: "npm",
				},
				versions: ["1.0.0", "1.0.1", "1.1.0"],
			};

			const result = OSVAffectedSchema.parse(versionsAffected);
			expect(result).toEqual(versionsAffected);
		});

		test("should validate affected with ranges only", () => {
			const rangesAffected = {
				package: {
					name: "vulnerable-pkg",
					ecosystem: "npm",
				},
				ranges: [
					{
						type: "SEMVER",
						events: [{ introduced: "0" }, { fixed: "1.2.0" }],
					},
				],
			};

			const result = OSVAffectedSchema.parse(rangesAffected);
			expect(result).toEqual(rangesAffected);
		});

		test("should reject affected without package", () => {
			const invalidAffected = {
				versions: ["1.0.0"],
			};

			expect(() => OSVAffectedSchema.parse(invalidAffected)).toThrow();
		});
	});

	describe("OSVVulnerabilitySchema", () => {
		test("should validate complete vulnerability", () => {
			const validVuln = {
				id: "GHSA-test-1234",
				summary: "Test vulnerability",
				details: "Detailed description of the vulnerability",
				modified: "2023-01-01T00:00:00Z",
				published: "2023-01-01T00:00:00Z",
				withdrawn: "2023-02-01T00:00:00Z",
				aliases: ["CVE-2023-1234"],
				related: ["GHSA-related-5678"],
				schema_version: "1.4.0",
				affected: [
					{
						package: {
							name: "test-package",
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
				database_specific: {
					severity: "HIGH",
					source: "test-source",
				},
				severity: [
					{
						type: "CVSS_V3",
						score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
					},
				],
				ecosystem_specific: {
					affected_functions: ["vulnerable_function"],
				},
				credits: [
					{
						name: "Security Researcher",
						contact: ["researcher@example.com"],
						type: "FINDER",
					},
				],
			};

			const result = OSVVulnerabilitySchema.parse(validVuln);
			expect(result).toEqual(validVuln);
		});

		test("should validate minimal vulnerability", () => {
			const minimalVuln = {
				id: "TEST-001",
			};

			const result = OSVVulnerabilitySchema.parse(minimalVuln);
			expect(result).toEqual(minimalVuln);
		});

		test("should validate vulnerability with CVSS scores", () => {
			const cvssVuln = {
				id: "TEST-CVSS",
				severity: [
					{
						type: "CVSS_V2",
						score: "AV:N/AC:L/Au:N/C:P/I:P/A:P/7.5",
					},
					{
						type: "CVSS_V3",
						score: "8.5",
					},
				],
			};

			const result = OSVVulnerabilitySchema.parse(cvssVuln);
			expect(result).toEqual(cvssVuln);
		});

		test("should reject vulnerability without id", () => {
			const invalidVuln = {
				summary: "Missing ID",
			};

			expect(() => OSVVulnerabilitySchema.parse(invalidVuln)).toThrow();
		});

		test("should handle empty arrays gracefully", () => {
			const emptyArrayVuln = {
				id: "TEST-EMPTY",
				aliases: [],
				related: [],
				affected: [],
				references: [],
				severity: [],
				credits: [],
			};

			const result = OSVVulnerabilitySchema.parse(emptyArrayVuln);
			expect(result).toEqual(emptyArrayVuln);
		});
	});

	describe("OSVResponseSchema", () => {
		test("should validate complete response", () => {
			const validResponse = {
				vulns: [
					{
						id: "GHSA-test-1",
						summary: "First vulnerability",
					},
					{
						id: "GHSA-test-2",
						summary: "Second vulnerability",
					},
				],
				next_page_token: "page2",
			};

			const result = OSVResponseSchema.parse(validResponse);
			expect(result).toEqual(validResponse);
		});

		test("should validate empty response", () => {
			const emptyResponse = {};

			const result = OSVResponseSchema.parse(emptyResponse);
			expect(result).toEqual({});
		});

		test("should validate response with only vulns", () => {
			const vulnsResponse = {
				vulns: [
					{
						id: "SINGLE-VULN",
					},
				],
			};

			const result = OSVResponseSchema.parse(vulnsResponse);
			expect(result).toEqual(vulnsResponse);
		});

		test("should validate response with only pagination token", () => {
			const tokenResponse = {
				next_page_token: "next-page",
			};

			const result = OSVResponseSchema.parse(tokenResponse);
			expect(result).toEqual(tokenResponse);
		});

		test("should handle null vulns array", () => {
			const nullVulnsResponse = {
				vulns: null,
			};

			// Schema should reject null vulns array
			expect(() => OSVResponseSchema.parse(nullVulnsResponse)).toThrow();
		});
	});

	describe("OSVBatchQuerySchema", () => {
		test("should validate batch query", () => {
			const validBatchQuery = {
				queries: [
					{
						package: {
							name: "lodash",
							ecosystem: "npm",
						},
						version: "4.17.21",
					},
					{
						commit: "abc123",
					},
					{
						package: {
							name: "express",
							ecosystem: "npm",
							purl: "pkg:npm/express@4.18.0",
						},
					},
				],
			};

			const result = OSVBatchQuerySchema.parse(validBatchQuery);
			expect(result).toEqual(validBatchQuery);
		});

		test("should validate empty batch query", () => {
			const emptyBatchQuery = {
				queries: [],
			};

			const result = OSVBatchQuerySchema.parse(emptyBatchQuery);
			expect(result).toEqual(emptyBatchQuery);
		});

		test("should reject batch query without queries array", () => {
			const invalidBatchQuery = {};

			expect(() => OSVBatchQuerySchema.parse(invalidBatchQuery)).toThrow();
		});

		test("should reject batch query with null queries", () => {
			const nullQueriesQuery = {
				queries: null,
			};

			expect(() => OSVBatchQuerySchema.parse(nullQueriesQuery)).toThrow();
		});
	});

	describe("OSVBatchResponseSchema", () => {
		test("should validate complete batch response", () => {
			const validBatchResponse = {
				results: [
					{
						vulns: [
							{
								id: "GHSA-batch-1",
								modified: "2023-01-01T00:00:00Z",
							},
							{
								id: "GHSA-batch-2",
								modified: "2023-01-02T00:00:00Z",
							},
						],
						next_page_token: "page2-query1",
					},
					{
						vulns: [
							{
								id: "GHSA-batch-3",
								modified: "2023-01-03T00:00:00Z",
							},
						],
					},
					{
						// Empty result
					},
				],
			};

			const result = OSVBatchResponseSchema.parse(validBatchResponse);
			expect(result).toEqual(validBatchResponse);
		});

		test("should validate empty batch response", () => {
			const emptyBatchResponse = {
				results: [],
			};

			const result = OSVBatchResponseSchema.parse(emptyBatchResponse);
			expect(result).toEqual(emptyBatchResponse);
		});

		test("should validate batch response with pagination tokens", () => {
			const paginatedBatchResponse = {
				results: [
					{
						vulns: [
							{
								id: "PAGINATED-1",
								modified: "2023-01-01T00:00:00Z",
							},
						],
						next_page_token: "page2-for-query1",
					},
					{
						vulns: [
							{
								id: "PAGINATED-2",
								modified: "2023-01-02T00:00:00Z",
							},
						],
						next_page_token: "page2-for-query2",
					},
				],
			};

			const result = OSVBatchResponseSchema.parse(paginatedBatchResponse);
			expect(result).toEqual(paginatedBatchResponse);
		});

		test("should reject batch response without results array", () => {
			const invalidBatchResponse = {};

			expect(() =>
				OSVBatchResponseSchema.parse(invalidBatchResponse),
			).toThrow();
		});

		test("should handle batch result with simplified vulnerability format", () => {
			const simplifiedBatchResponse = {
				results: [
					{
						vulns: [
							{
								id: "SIMPLE-1",
								modified: "2023-01-01T00:00:00Z",
							},
						],
					},
				],
			};

			const result = OSVBatchResponseSchema.parse(simplifiedBatchResponse);
			expect(result).toEqual(simplifiedBatchResponse);
		});
	});

	describe("Real-world data compatibility", () => {
		test("should handle actual OSV API response structure", () => {
			// Based on actual OSV API response format
			const realWorldResponse = {
				vulns: [
					{
						id: "GHSA-c6rq-rjc2-86v2",
						summary: "lodash vulnerable to Prototype Pollution",
						details:
							"lodash prior to 4.17.12 is vulnerable to Prototype Pollution.",
						aliases: ["CVE-2019-10744"],
						modified: "2023-02-16T23:10:44Z",
						published: "2019-07-15T19:15:00Z",
						database_specific: {
							cwe_ids: ["CWE-1321"],
							severity: "HIGH",
							github_reviewed: true,
						},
						references: [
							{
								type: "ADVISORY",
								url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
							},
							{
								type: "WEB",
								url: "https://github.com/lodash/lodash/pull/4336",
							},
						],
						affected: [
							{
								package: {
									ecosystem: "npm",
									name: "lodash",
								},
								ranges: [
									{
										type: "SEMVER",
										events: [
											{
												introduced: "0",
											},
											{
												fixed: "4.17.12",
											},
										],
									},
								],
							},
						],
						schema_version: "1.4.0",
					},
				],
			};

			const result = OSVResponseSchema.parse(realWorldResponse);
			expect(result.vulns).toHaveLength(1);
			expect(result.vulns?.[0]?.id).toBe("GHSA-c6rq-rjc2-86v2");
		});

		test("should handle batch response with mixed result types", () => {
			const mixedBatchResponse = {
				results: [
					{
						vulns: [
							{
								id: "MIXED-1",
								modified: "2023-01-01T00:00:00Z",
							},
						],
						next_page_token: "has-more",
					},
					{
						// No vulnerabilities found for this query
					},
					{
						vulns: [
							{
								id: "MIXED-2",
								modified: "2023-01-02T00:00:00Z",
							},
							{
								id: "MIXED-3",
								modified: "2023-01-03T00:00:00Z",
							},
						],
					},
				],
			};

			const result = OSVBatchResponseSchema.parse(mixedBatchResponse);
			expect(result.results).toHaveLength(3);
			expect(result.results[0]?.vulns).toHaveLength(1);
			expect(result.results[1]?.vulns).toBeUndefined();
			expect(result.results[2]?.vulns).toHaveLength(2);
		});
	});

	describe("Error handling", () => {
		test("should provide descriptive error messages", () => {
			try {
				OSVVulnerabilitySchema.parse({
					// Missing required 'id' field
					summary: "Missing ID",
				});
			} catch (error) {
				expect(error).toBeDefined();
				expect(String(error)).toContain("id");
			}
		});

		test("should handle deeply nested validation errors", () => {
			try {
				OSVVulnerabilitySchema.parse({
					id: "TEST-NESTED-ERROR",
					affected: [
						{
							// Missing required 'package' field
							versions: ["1.0.0"],
						},
					],
				});
			} catch (error) {
				expect(error).toBeDefined();
			}
		});

		test("should handle type mismatches", () => {
			try {
				OSVQuerySchema.parse({
					version: 123, // Should be string
				});
			} catch (error) {
				expect(error).toBeDefined();
			}
		});
	});
});
