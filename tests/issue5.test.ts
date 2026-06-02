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

const TEST_DB = "packablock_test_issue5.sqlite";

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

describe("Issue #5 - Visualization Tree API Endpoint (/api/v1/repo/:id/tree)", () => {
	const owner = "issue5owner";
	const repoName = "issue5-repo";
	let repoId = 0;
	let registrationToken = "";

	beforeAll(async () => {
		// Register a test repo
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner,
				repo: repoName,
				isPremium: false, // Standard registration yields an active token immediately
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

	it("should return a 400 Bad Request for an invalid non-integer ID format", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/api/v1/repo/not-an-integer/tree",
		});
		expect(res.statusCode).toBe(400);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Bad Request");
		expect(data.message).toContain("Invalid repository ID format");
	});

	it("should return a 404 Not Found for a non-existent repo ID", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/api/v1/repo/999999/tree",
		});
		expect(res.statusCode).toBe(404);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Not Found");
		expect(data.message).toContain("not registered");
	});

	it("should return a 404 Not Found if no package history log exists yet", async () => {
		const res = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${repoId}/tree`,
		});
		expect(res.statusCode).toBe(404);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Not Found");
		expect(data.message).toContain("No package history log exists");
	});

	it("should construct correct tree & graph payloads for a standard active log and resolve badges", async () => {
		// 1. Create a block 0 containing multiple types of metadata signatures to verify badge resolution
		const block0 = createValidChainPair(
			0,
			GENESIS_PREV_HASH,
			{
				packages: {
					"test-lib": {
						version: "1.0.0",
						integrity: "sha512-testHash",
					},
				},
			},
			{
				committer: "Aaron Bronow <aaron@example.com>",
				git_actor: "Aaron Bronow <aaron@example.com>",
				ssh_key_fingerprint: "SHA256:abcd1234ssh",
			},
		);

		// 2. Push block 0 to the repository log
		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": registrationToken,
				"Content-Type": "text/plain",
			},
			body: block0.chainFragment,
		});
		expect(pushRes.statusCode).toBe(200);

		// 3. Request the tree endpoint
		const treeRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${repoId}/tree`,
		});
		expect(treeRes.statusCode).toBe(200);

		const payload = JSON.parse(treeRes.body);
		expect(payload.success).toBe(true);
		expect(payload.repository).toBe(
			`${owner.toLowerCase()}/${repoName.toLowerCase()}`,
		);
		expect(payload.blockCount).toBe(1);

		// Verify Tree structure
		const tree = payload.tree;
		expect(tree.id).toBe(GENESIS_PREV_HASH);
		expect(tree.name).toBe("Genesis Anchor");
		expect(tree.type).toBe("root");
		expect(tree.children).toHaveLength(1);

		const childNode = tree.children[0];
		expect(childNode.id).toBe(block0.metaHash);
		expect(childNode.name).toBe("Block #0");
		expect(childNode.block_index).toBe(0);
		expect(childNode.version).toBe("1.0.0");
		expect(childNode.data_hash).toBe(block0.dataHash);
		expect(childNode.prev_meta_hash).toBe(GENESIS_PREV_HASH);
		expect(childNode.meta_hash).toBe(block0.metaHash);
		// Identity badge should prioritize SSH fingerprint over git actor
		expect(childNode.identityBadge).toBe("SSH: SHA256:abcd1234ssh");
		expect(childNode.type).toBe("block");

		// Verify Graph structure
		const graph = payload.graph;
		expect(graph.nodes).toHaveLength(2); // Genesis Anchor + Block 0
		expect(graph.edges).toHaveLength(1); // Genesis Anchor -> Block 0

		expect(graph.nodes[0].id).toBe(GENESIS_PREV_HASH);
		expect(graph.nodes[0].type).toBe("root");

		expect(graph.nodes[1].id).toBe(block0.metaHash);
		expect(graph.nodes[1].block_index).toBe(0);
		expect(graph.nodes[1].identityBadge).toBe("SSH: SHA256:abcd1234ssh");

		expect(graph.edges[0].source).toBe(GENESIS_PREV_HASH);
		expect(graph.edges[0].target).toBe(block0.metaHash);
	});

	it("should resolve identity badge for OIDC actor claims correctly", async () => {
		// Clean the database log so we can push fresh
		// Register another repo to keep tests isolated and clean
		const oidcOwner = "oidcowner";
		const oidcRepoName = "oidc-repo";
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner: oidcOwner,
				repo: oidcRepoName,
				isPremium: false,
			},
		});
		const { registrationToken: token } = JSON.parse(res.body);

		const repoRecord = getRepositoryByPath(oidcOwner, oidcRepoName);
		expect(repoRecord).not.toBeNull();
		const id = repoRecord!.id;

		// Create block 0 with OIDC claims
		const block = createValidChainPair(
			0,
			GENESIS_PREV_HASH,
			{ packages: {} },
			{
				oidc_claims: {
					actor: "aaron-github-runner",
					workflow: "ci.yml",
				},
			},
		);

		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": token,
				"Content-Type": "text/plain",
			},
			body: block.chainFragment,
		});
		expect(pushRes.statusCode).toBe(200);

		const treeRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${id}/tree`,
		});
		expect(treeRes.statusCode).toBe(200);
		const payload = JSON.parse(treeRes.body);
		expect(payload.tree.children[0].identityBadge).toBe(
			"OIDC: aaron-github-runner",
		);
	});

	it("should assemble active logs and archived logs across key rollover/rotations linearly", async () => {
		// We will test on a new repository
		const rollOwner = "rolloverowner";
		const rollRepoName = "rollover-repo";
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner: rollOwner,
				repo: rollRepoName,
				isPremium: false,
			},
		});
		const { registrationToken: token } = JSON.parse(res.body);

		const repoRecord = getRepositoryByPath(rollOwner, rollRepoName);
		expect(repoRecord).not.toBeNull();
		const id = repoRecord!.id;

		// 1. Push Block 0 (Epoch 0)
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			step: "genesis",
		});
		let pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": token,
				"Content-Type": "text/plain",
			},
			body: block0.chainFragment,
		});
		expect(pushRes.statusCode).toBe(200);

		// 2. Push Block 1 (Epoch 0)
		const block1 = createValidChainPair(1, block0.metaHash, { step: "update" });
		const epoch0Fragment = `${block0.chainFragment}\n${block1.chainFragment}`;
		pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": token,
				"Content-Type": "text/plain",
			},
			body: epoch0Fragment,
		});
		expect(pushRes.statusCode).toBe(200);

		// 3. Initiate Key Rollover (creates Epoch 1 starting with rollover block 0 linking to block 1)
		const rolloverBlock = createValidChainPair(0, block1.metaHash, {
			genesis_rollover: true,
			new_epoch: 1,
		});
		const rolloverRes = await server.inject({
			method: "POST",
			url: `/api/v1/repo/${rollOwner}/${rollRepoName}/rollover`,
			headers: {
				"X-Repo-Token": token,
				"Content-Type": "application/json",
			},
			body: {
				previous_chain_hash: block1.metaHash,
				new_genesis_block: rolloverBlock.chainFragment,
			},
		});
		expect(rolloverRes.statusCode).toBe(200);

		// 4. Request the /tree endpoint to verify both epochs are assembled
		const treeRes = await server.inject({
			method: "GET",
			url: `/api/v1/repo/${id}/tree`,
		});
		expect(treeRes.statusCode).toBe(200);

		const payload = JSON.parse(treeRes.body);
		expect(payload.blockCount).toBe(3); // Epoch 0 (Block 0, 1) + Epoch 1 (Block 0)

		// Verify linear hierarchy
		const tree = payload.tree;
		expect(tree.id).toBe(GENESIS_PREV_HASH);
		expect(tree.children).toHaveLength(1);

		const node0 = tree.children[0];
		expect(node0.id).toBe(block0.metaHash);
		expect(node0.children).toHaveLength(1);

		const node1 = node0.children[0];
		expect(node1.id).toBe(block1.metaHash);
		expect(node1.children).toHaveLength(1);

		const nodeRollover = node1.children[0];
		expect(nodeRollover.id).toBe(rolloverBlock.metaHash);
		expect(nodeRollover.type).toBe("rollover");
		expect(nodeRollover.children).toHaveLength(0);

		// Verify complete graph nodes and edges
		const graph = payload.graph;
		expect(graph.nodes).toHaveLength(4); // Anchor + Block 0 + Block 1 + Rollover Block 0
		expect(graph.edges).toHaveLength(3); // 3 edges linking them linearly

		expect(graph.edges[0]).toEqual({
			source: GENESIS_PREV_HASH,
			target: block0.metaHash,
		});
		expect(graph.edges[1]).toEqual({
			source: block0.metaHash,
			target: block1.metaHash,
		});
		expect(graph.edges[2]).toEqual({
			source: block1.metaHash,
			target: rolloverBlock.metaHash,
		});
	});
});
