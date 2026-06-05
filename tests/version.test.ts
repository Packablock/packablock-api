import { describe, expect, it } from "bun:test";
import { server } from "../src/server.js";
import pkg from "../package.json";

describe("Registry Version API Endpoints", () => {
	it("should return the correct version from GET /version", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/version",
		});

		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data).toEqual({
			success: true,
			version: pkg.version,
			service: "packablock-registry",
		});
	});

	it("should return the correct version from GET /api/v1/version", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/api/v1/version",
		});

		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data).toEqual({
			success: true,
			version: pkg.version,
			service: "packablock-registry",
		});
	});
});
