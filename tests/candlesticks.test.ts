import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { server } from "../src/server.ts";
import { initDb, saveCachedPackage } from "../src/database.ts";
import {
	sha256,
	deterministicMetaHash,
	GENESIS_PREV_HASH,
} from "../src/verify.ts";
import YAML from "yaml";
import fs from "node:fs";
import path from "node:path";

const TEST_DB = "packablock_test_candlesticks.sqlite";

function createValidChainPair(
	index: number,
	prevMetaHash: string,
	dataObj: any,
) {
	const dataDocStr = YAML.stringify(dataObj);
	const dataHash = sha256(dataDocStr.trim());

	const metaObjWithoutHash = {
		version: "1.0.0",
		block_index: index,
		timestamp: new Date(Date.now() - (5 - index) * 60000).toISOString(),
		hashing_strategy: "raw" as const,
		data_hash: dataHash,
		prev_meta_hash: prevMetaHash,
	};

	const metaHash = deterministicMetaHash(metaObjWithoutHash);
	const metaObj = {
		...metaObjWithoutHash,
		meta_hash: metaHash,
	};

	const metaDocStr = YAML.stringify({ "$yaml-chain-meta": metaObj });

	return {
		dataHash,
		metaHash,
		chainFragment: `---\n${dataDocStr}---\n${metaDocStr}`,
	};
}

beforeAll(() => {
	process.env.DATABASE_FILE = TEST_DB;

	const dbFile = path.join(process.cwd(), TEST_DB);
	if (fs.existsSync(dbFile)) {
		try {
			fs.unlinkSync(dbFile);
		} catch (e) {}
	}
	initDb();
});

afterAll(() => {
	const dbFile = path.join(process.cwd(), TEST_DB);
	if (fs.existsSync(dbFile)) {
		try {
			fs.unlinkSync(dbFile);
		} catch (e) {}
	}
});

describe("Registry Candlesticks API Endpoint", () => {
	const owner = "candlestickowner";
	const repo = "candlestick-repo";
	const token = "pb_reg_candlestick_token_123";

	it("should parse constraints, trace history, and return candlesticks YAML", async () => {
		// 1. Register the repository
		const regRes = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner,
				repo,
				isPremium: false,
			},
		});
		expect(regRes.statusCode).toBe(200);
		const regData = JSON.parse(regRes.body);
		const actualToken = regData.registrationToken;

		// 2. Setup mock packages in the cache database to avoid npm fetching
		saveCachedPackage("lodash", "4.20.0");
		saveCachedPackage("express", "4.18.99");

		// 3. Build block 0 (Genesis / First installment)
		const block0Data = {
			"package.json": {
				constraints: [{ lodash: "^4.17.21" }, { express: "~4.18.0" }],
			},
			lockfiles: {
				"package-lock.json": {
					packages: [{ lodash: "4.17.21" }, { express: "4.18.0" }],
				},
			},
		};

		const b0 = createValidChainPair(0, GENESIS_PREV_HASH, block0Data);

		// 4. Build block 1 (Drifted versions)
		const block1Data = {
			"package.json": {
				constraints: [{ lodash: "^4.17.21" }, { express: "~4.18.0" }],
			},
			lockfiles: {
				"package-lock.json": {
					packages: [{ lodash: "4.18.0" }, { express: "4.18.1" }],
				},
			},
		};

		const b1 = createValidChainPair(1, b0.metaHash, block1Data);

		const fullChain = b0.chainFragment + b1.chainFragment;

		// 5. Push the chain to registry
		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/yaml",
				"x-repo-token": actualToken,
			},
			body: fullChain,
		});
		expect(pushRes.statusCode).toBe(200);

		// 6. Query GET /api/v1/repo/:owner/:repo/candlesticks
		const candleRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${owner}/${repo}/candlesticks`,
		});

		expect(candleRes.statusCode).toBe(200);
		expect(candleRes.headers["content-type"]).toContain("yaml");

		const parsedCandles = YAML.parse(candleRes.body);
		expect(Array.isArray(parsedCandles)).toBe(true);
		expect(parsedCandles).toHaveLength(2);

		const lodashCandle = parsedCandles.find((c: any) => c.package === "lodash");
		expect(lodashCandle).toBeDefined();
		expect(lodashCandle.constraint).toBe("^4.17.21");
		expect(lodashCandle.min_version).toBe("4.17.21");
		expect(lodashCandle.max_version).toBe("4.99.99");
		expect(lodashCandle.type).toBe("caret");
		expect(lodashCandle.current_pinned_version).toBe("4.18.0");
		expect(lodashCandle.first_seen_version).toBe("4.17.21");
		expect(lodashCandle.latest_upstream_version).toBe("4.20.0");
		expect(lodashCandle.first_seen_timestamp).toBeDefined();
		expect(lodashCandle.latest_upstream_timestamp).toBeDefined();

		const expressCandle = parsedCandles.find(
			(c: any) => c.package === "express",
		);
		expect(expressCandle).toBeDefined();
		expect(expressCandle.constraint).toBe("~4.18.0");
		expect(expressCandle.min_version).toBe("4.18.0");
		expect(expressCandle.max_version).toBe("4.18.999");
		expect(expressCandle.type).toBe("tilde");
		expect(expressCandle.current_pinned_version).toBe("4.18.1");
		expect(expressCandle.first_seen_version).toBe("4.18.0");
		expect(expressCandle.latest_upstream_version).toBe("4.18.99");
	});

	it("should return 404 for unregistered repository", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/api/v1/repo/nonexistent/repo/candlesticks",
		});
		expect(res.statusCode).toBe(404);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Not Found");
	});

	it("should return 404 for registered repository with no blocks", async () => {
		const ownerNoBlocks = "noblocksowner";
		const repoNoBlocks = "noblocks-repo";
		const regRes = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner: ownerNoBlocks,
				repo: repoNoBlocks,
				isPremium: false,
			},
		});
		expect(regRes.statusCode).toBe(200);

		const res = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${ownerNoBlocks}/${repoNoBlocks}/candlesticks`,
		});
		expect(res.statusCode).toBe(404);
		const data = JSON.parse(res.body);
		expect(data.message).toContain("No package history log exists");
	});

	it("should return empty array if last block has no package.json constraints", async () => {
		const ownerNoConstraints = "noconstraintsowner";
		const repoNoConstraints = "noconstraints-repo";

		const regRes = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner: ownerNoConstraints,
				repo: repoNoConstraints,
				isPremium: false,
			},
		});
		expect(regRes.statusCode).toBe(200);
		const actualToken = JSON.parse(regRes.body).registrationToken;

		const blockData = {
			lockfiles: {
				"package-lock.json": {
					packages: [{ lodash: "4.17.21" }],
				},
			},
		};
		const b0 = createValidChainPair(0, GENESIS_PREV_HASH, blockData);

		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/yaml",
				"x-repo-token": actualToken,
			},
			body: b0.chainFragment,
		});
		expect(pushRes.statusCode).toBe(200);

		const res = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${ownerNoConstraints}/${repoNoConstraints}/candlesticks`,
		});
		expect(res.statusCode).toBe(200);
		const parsed = YAML.parse(res.body);
		expect(parsed).toEqual([]);
	});
});
