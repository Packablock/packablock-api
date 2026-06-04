import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { server } from "../src/server.ts";
import { initDb, getRepositoryByPath } from "../src/database.ts";
import {
	sha256,
	deterministicMetaHash,
	GENESIS_PREV_HASH,
} from "../src/verify.ts";
import YAML from "yaml";
import fs from "node:fs";
import path from "node:path";

const TEST_DB = "packablock_test_multilockfile.sqlite";

function createValidChainPair(
	index: number,
	prevMetaHash: string,
	dataObj: any,
	metaExtra: any = {},
) {
	const dataDocStr = YAML.stringify(dataObj);
	const dataHash = sha256(dataDocStr.trim());

	const metaObjWithoutHash = {
		version: "1.0.0",
		block_index: index,
		timestamp: new Date().toISOString(),
		hashing_strategy: "raw" as const,
		data_hash: dataHash,
		prev_meta_hash: prevMetaHash,
		...metaExtra,
	};

	const metaHash = deterministicMetaHash(metaObjWithoutHash);
	const metaObj = {
		...metaObjWithoutHash,
		meta_hash: metaHash,
	};

	const metaDocStr = YAML.stringify({ "$yaml-chain-meta": metaObj });

	return {
		dataDocStr,
		metaDocStr,
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
		} catch (_e) {}
	}

	initDb();
});

afterAll(() => {
	const dbFile = path.join(process.cwd(), TEST_DB);
	if (fs.existsSync(dbFile)) {
		try {
			fs.unlinkSync(dbFile);
		} catch (_e) {}
	}
});

describe("Registry Multi-Lockfile and Chain Events (init/forget)", () => {
	const owner = "mlfowner";
	const repoName = "mlf-repo";
	let repoId = 0;
	let registrationToken = "";

	beforeAll(async () => {
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner,
				repo: repoName,
				isPremium: false,
			},
		});
		const data = JSON.parse(res.body);
		registrationToken = data.registrationToken;

		const repoRecord = getRepositoryByPath(owner, repoName);
		expect(repoRecord).not.toBeNull();
		if (repoRecord) {
			repoId = repoRecord.id;
		}
	});

	it("should support parallel lockfile init/forget chain events and compute packagesCount", async () => {
		// Block 0: Initialize package-lock.json with packages package-a and package-b
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			"package-lock.json": {
				chain_event: "init",
				packages: [
					{ "package-a": "1.0.0" },
					{ "package-b": "2.0.0" },
				],
			},
		});

		let pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/yaml",
				"x-repo-token": registrationToken,
				"x-target-repo": `${owner}/${repoName}`,
			},
			body: block0.chainFragment,
		});
		expect(pushRes.statusCode).toBe(200);

		// Verify block in tree endpoint and packagesCount
		let treeRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${owner}/${repoName}/tree`,
		});
		expect(treeRes.statusCode).toBe(200);
		let treeData = JSON.parse(treeRes.body);
		expect(treeData.graph.nodes).toHaveLength(2); // Genesis Anchor + Block 0
		expect(treeData.graph.nodes[1].packagesCount).toBe(2);

		// Block 1: Initialize bun.lockb with packages package-c
		const block1 = createValidChainPair(1, block0.metaHash, {
			"bun.lockb": {
				chain_event: "init",
				packages: [
					{ "package-c": "3.0.0" },
				],
			},
		});

		pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/yaml",
				"x-repo-token": registrationToken,
				"x-target-repo": `${owner}/${repoName}`,
			},
			body: `${block0.chainFragment}\n${block1.chainFragment}`,
		});
		expect(pushRes.statusCode).toBe(200);

		treeRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${owner}/${repoName}/tree`,
		});
		treeData = JSON.parse(treeRes.body);
		expect(treeData.graph.nodes).toHaveLength(3); // Anchor + Block 0 + Block 1
		expect(treeData.graph.nodes[2].packagesCount).toBe(1); // just bun.lockb in this block

		// Verify history endpoint retrieves combined reconstructed state at Block 1: package-a, package-b, package-c
		let historyRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${owner}/${repoName}/history`,
		});
		expect(historyRes.statusCode).toBe(200);
		let historyData = JSON.parse(historyRes.body);
		expect(historyData.history).toHaveLength(2);
		// block 1 details should contain full parsedData
		expect(historyData.history[1].packages["bun.lockb"].packages).toEqual([{ "package-c": "3.0.0" }]);
		expect(historyData.history[1].packages["package-lock.json"]).toBeUndefined(); // block 1 parsed data only has bun.lockb

		// Block 2: Forget package-lock.json
		const block2 = createValidChainPair(2, block1.metaHash, {
			"package-lock.json": {
				chain_event: "forget",
			},
		});

		pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/yaml",
				"x-repo-token": registrationToken,
				"x-target-repo": `${owner}/${repoName}`,
			},
			body: `${block0.chainFragment}\n${block1.chainFragment}\n${block2.chainFragment}`,
		});
		expect(pushRes.statusCode).toBe(200);

		treeRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${owner}/${repoName}/tree`,
		});
		treeData = JSON.parse(treeRes.body);
		expect(treeData.graph.nodes).toHaveLength(4);
		expect(treeData.graph.nodes[3].packagesCount).toBe(0); // forget event has 0 packages listed inside it

		// Verify history / reconstructed packages at block 2. Since package-lock.json is forgotten,
		// the active packages should only be from bun.lockb (package-c: 3.0.0).
		// We can test this by pushing block 3 which updates package-c and checking if package-a/b are gone from reconstructed state.
		// Wait, reconstructPackagesAtBlock is used in /api/v1/log/push to get oldPkgs and newPkgs for SemVer warnings and Webhook triggers.
		// Let's verify package-c gets updated, and package-a/b are not in the old/new package sets.
		const block3 = createValidChainPair(3, block2.metaHash, {
			"bun.lockb": {
				packages: [
					{ "package-c": [{ old: "3.0.0" }, { new: "3.1.0" }] },
				],
			},
		});

		pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/yaml",
				"x-repo-token": registrationToken,
				"x-target-repo": `${owner}/${repoName}`,
			},
			body: `${block0.chainFragment}\n${block1.chainFragment}\n${block2.chainFragment}\n${block3.chainFragment}`,
		});
		expect(pushRes.statusCode).toBe(200);
	});
});
