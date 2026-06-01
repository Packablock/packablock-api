import {
	describe,
	it,
	expect,
	beforeAll,
	afterAll,
	beforeEach,
} from "bun:test";
import { server } from "../src/server.ts";
import { initDb } from "../src/database.ts";
import {
	sha256,
	deterministicMetaHash,
	GENESIS_PREV_HASH,
} from "../src/verify.ts";
import YAML from "yaml";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const TEST_DB = "packablock_test_auditing.sqlite";

// Store original fetch
const originalFetch = globalThis.fetch;

// Helper to generate a valid chain block pair
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
	// Set isolated test database environment variable
	process.env.DATABASE_FILE = TEST_DB;

	// Ensure any stale database file is removed
	const dbFile = path.join(process.cwd(), TEST_DB);
	if (fs.existsSync(dbFile)) {
		try {
			fs.unlinkSync(dbFile);
		} catch (e) {}
	}

	// Initialize database and schema for testing
	initDb();
});

afterAll(() => {
	// Restore original fetch
	globalThis.fetch = originalFetch;

	// Teardown and clean up the test database file
	const dbFile = path.join(process.cwd(), TEST_DB);
	if (fs.existsSync(dbFile)) {
		try {
			fs.unlinkSync(dbFile);
		} catch (e) {}
	}
});

describe("Registry Auditing and Webhooks", () => {
	let repoToken = "";
	const owner = "auditowner";
	const repoName = "audit-repo";

	beforeAll(async () => {
		// Register a standard repo for testing
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
		repoToken = data.registrationToken;
	});

	describe("Webhooks API CRUD", () => {
		let webhookId: number;

		it("should register a new webhook with URL and secret successfully", async () => {
			const res = await server.inject({
				method: "POST",
				url: `/api/v1/repo/${owner}/${repoName}/webhooks`,
				payload: {
					url: "http://my-mock-webhook.local/callback",
					secret: "my-webhook-secret",
				},
			});

			expect(res.statusCode).toBe(200);
			const data = JSON.parse(res.body);
			expect(data.success).toBe(true);
			expect(data.message).toBe("Webhook registered successfully.");
			expect(data.webhook).toBeDefined();
			expect(data.webhook.url).toBe("http://my-mock-webhook.local/callback");
			expect(data.webhook.secret).toBe("my-webhook-secret");
			expect(data.webhook.id).toBeDefined();

			webhookId = data.webhook.id;
		});

		it("should reject webhook registration with missing url", async () => {
			const res = await server.inject({
				method: "POST",
				url: `/api/v1/repo/${owner}/${repoName}/webhooks`,
				payload: {
					secret: "my-webhook-secret",
				},
			});

			expect(res.statusCode).toBe(400);
			const data = JSON.parse(res.body);
			expect(data.error).toBe("Bad Request");
			expect(data.message).toContain("url");
		});

		it("should list registered webhooks for the repository", async () => {
			const res = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${owner}/${repoName}/webhooks`,
			});

			expect(res.statusCode).toBe(200);
			const data = JSON.parse(res.body);
			expect(data.success).toBe(true);
			expect(data.webhooks).toBeArray();
			expect(data.webhooks.length).toBe(1);
			expect(data.webhooks[0].id).toBe(webhookId);
			expect(data.webhooks[0].url).toBe(
				"http://my-mock-webhook.local/callback",
			);
		});

		it("should return 404 when listing webhooks on non-existent repository", async () => {
			const res = await server.inject({
				method: "GET",
				url: "/api/v1/repo/nonexistent/repo/webhooks",
			});

			expect(res.statusCode).toBe(404);
		});

		it("should successfully delete a registered webhook", async () => {
			const res = await server.inject({
				method: "DELETE",
				url: `/api/v1/repo/${owner}/${repoName}/webhooks/${webhookId}`,
			});

			expect(res.statusCode).toBe(200);
			const data = JSON.parse(res.body);
			expect(data.success).toBe(true);
			expect(data.message).toBe("Webhook deleted successfully.");

			// Verify it's gone
			const listRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${owner}/${repoName}/webhooks`,
			});
			const listData = JSON.parse(listRes.body);
			expect(listData.webhooks.length).toBe(0);
		});

		it("should return 404 when deleting non-existent webhook ID", async () => {
			const res = await server.inject({
				method: "DELETE",
				url: `/api/v1/repo/${owner}/${repoName}/webhooks/99999`,
			});

			expect(res.statusCode).toBe(404);
		});
	});

	describe("Log History and Signatures Auditing", () => {
		const auditRepo = "audit-chain-repo";
		let auditToken = "";

		beforeAll(async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/acme/new-account",
				payload: {
					owner,
					repo: auditRepo,
					isPremium: false,
				},
			});
			const data = JSON.parse(res.body);
			auditToken = data.registrationToken;
		});

		it("should push a valid 2-block package chain and retrieve its audit history & sigs", async () => {
			// Construct Block 0 (Genesis)
			const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
				packages: {
					"packa-block": {
						version: "1.0.0",
						integrity: "sha512-genesisHash",
					},
				},
			});

			// Construct Block 1
			const block1 = createValidChainPair(
				1,
				block0.metaHash,
				{
					packages: {
						"packa-block": {
							version: "1.1.0",
							integrity: "sha512-bumpedHash",
						},
					},
				},
				{
					committer: "Aaron Bronow",
					signature: "gpg-signature-placeholder",
					oidc_claims: {
						actor: "aaron-github",
						workflow: "release.yml",
					},
				},
			);

			// Combine into multi-doc string
			const fullChain = `${block0.chainFragment}\n${block1.chainFragment}\n`;

			// Push to registry
			const pushRes = await server.inject({
				method: "POST",
				url: "/api/v1/log/push",
				headers: {
					"X-Repo-Token": auditToken,
					"Content-Type": "text/plain",
				},
				body: fullChain,
			});

			expect(pushRes.statusCode).toBe(200);
			const pushData = JSON.parse(pushRes.body);
			expect(pushData.success).toBe(true);
			expect(pushData.blockCount).toBe(2);

			// Test GET /history
			const historyRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${owner}/${auditRepo}/history`,
			});

			expect(historyRes.statusCode).toBe(200);
			const historyData = JSON.parse(historyRes.body);
			expect(historyData.success).toBe(true);
			expect(historyData.blockCount).toBe(2);
			expect(historyData.history).toHaveLength(2);

			// Assert Block 0 history
			expect(historyData.history[0].blockIndex).toBe(0);
			expect(historyData.history[0].prevMetaHash).toBe(GENESIS_PREV_HASH);
			expect(historyData.history[0].dataHash).toBe(block0.dataHash);
			expect(historyData.history[0].metaHash).toBe(block0.metaHash);
			expect(historyData.history[0].packages["packa-block"].version).toBe(
				"1.0.0",
			);

			// Assert Block 1 history
			expect(historyData.history[1].blockIndex).toBe(1);
			expect(historyData.history[1].prevMetaHash).toBe(block0.metaHash);
			expect(historyData.history[1].dataHash).toBe(block1.dataHash);
			expect(historyData.history[1].metaHash).toBe(block1.metaHash);
			expect(historyData.history[1].packages["packa-block"].version).toBe(
				"1.1.0",
			);

			// Test GET /sigs
			const sigsRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${owner}/${auditRepo}/sigs`,
			});

			expect(sigsRes.statusCode).toBe(200);
			const sigsData = JSON.parse(sigsRes.body);
			expect(sigsData.success).toBe(true);
			expect(sigsData.blockCount).toBe(2);
			expect(sigsData.signatures).toHaveLength(2);

			// Assert Block 0 signatures
			expect(sigsData.signatures[0].blockIndex).toBe(0);
			expect(sigsData.signatures[0].committer).toBeNull();
			expect(sigsData.signatures[0].signature).toBeNull();
			expect(sigsData.signatures[0].oidcClaims).toBeNull();

			// Assert Block 1 signatures
			expect(sigsData.signatures[1].blockIndex).toBe(1);
			expect(sigsData.signatures[1].committer).toBe("Aaron Bronow");
			expect(sigsData.signatures[1].signature).toBe(
				"gpg-signature-placeholder",
			);
			expect(sigsData.signatures[1].oidcClaims.actor).toBe("aaron-github");
			expect(sigsData.signatures[1].oidcClaims.workflow).toBe("release.yml");
		});
	});

	describe("Outbound Webhooks Alerting Pipeline", () => {
		const hookRepo = "hook-test-repo";
		let hookToken = "";
		let fetchedPayloads: Array<{ url: string; options: any }> = [];

		beforeAll(async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/acme/new-account",
				payload: {
					owner,
					repo: hookRepo,
					isPremium: false,
				},
			});
			const data = JSON.parse(res.body);
			hookToken = data.registrationToken;
		});

		beforeEach(() => {
			fetchedPayloads = [];
			// Mock global fetch to capture webhook invocations
			(globalThis as any).fetch = async (url: any, options: any) => {
				fetchedPayloads.push({ url: url.toString(), options });
				return {
					ok: true,
					status: 200,
					json: async () => ({}),
				} as Response;
			};
		});

		it("should trigger a push_success webhook event with a valid HMAC-SHA256 signature", async () => {
			// Register webhook first
			const registerWebhookRes = await server.inject({
				method: "POST",
				url: `/api/v1/repo/${owner}/${hookRepo}/webhooks`,
				payload: {
					url: "http://webhook-target.local/alert",
					secret: "super-secret-key",
				},
			});
			expect(registerWebhookRes.statusCode).toBe(200);

			// Construct a valid block
			const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
				packages: {
					"test-webhook": {
						version: "2.0.0",
						integrity: "sha512-webhookHash",
					},
				},
			});

			const fullChain = `${block0.chainFragment}\n`;

			// Push chain
			const pushRes = await server.inject({
				method: "POST",
				url: "/api/v1/log/push",
				headers: {
					"X-Repo-Token": hookToken,
					"Content-Type": "text/plain",
				},
				body: fullChain,
			});

			expect(pushRes.statusCode).toBe(200);

			// Wait briefly since webhooks are dispatched asynchronously
			await new Promise((resolve) => setTimeout(resolve, 100));

			// Assert webhook was fired
			expect(fetchedPayloads).toHaveLength(1);
			const { url, options } = fetchedPayloads[0]!;
			expect(url).toBe("http://webhook-target.local/alert");
			expect(options.method).toBe("POST");
			expect(options.headers["Content-Type"]).toBe("application/json");
			expect(options.headers["User-Agent"]).toBe(
				"Packablock-Registry-Webhooks",
			);
			expect(options.headers["X-Packablock-Signature"]).toBeDefined();

			// Parse body
			const bodyObj = JSON.parse(options.body);
			expect(bodyObj.event).toBe("push_success");
			expect(bodyObj.repository).toBe(`${owner}/${hookRepo}`);
			expect(bodyObj.timestamp).toBeDefined();
			expect(bodyObj.details.blockCount).toBe(1);
			expect(bodyObj.details.lastBlockHash).toBe(block0.metaHash);

			// Verify HMAC signature
			const signatureHeader = options.headers["X-Packablock-Signature"];
			const calculatedSig = crypto
				.createHmac("sha256", "super-secret-key")
				.update(options.body)
				.digest("hex");
			expect(signatureHeader).toBe(calculatedSig);
		});

		it("should trigger a push_failed_tampered webhook event when pushing a tampered chain", async () => {
			// Register webhook
			const registerWebhookRes = await server.inject({
				method: "POST",
				url: `/api/v1/repo/${owner}/${hookRepo}/webhooks`,
				payload: {
					url: "http://webhook-target.local/alert-fail",
					secret: "fail-secret-key",
				},
			});
			expect(registerWebhookRes.statusCode).toBe(200);

			// Construct a valid block, then tamper with the data
			const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
				packages: {
					"test-webhook": {
						version: "2.0.0",
						integrity: "sha512-webhookHash",
					},
				},
			});

			// Tamper the data doc string but keep metadata the same
			const tamperedDataDocStr = block0.dataDocStr.replace("2.0.0", "9.9.9");
			const tamperedChain = `---\n${tamperedDataDocStr}---\n${block0.metaDocStr}\n`;

			// Push tampered chain
			const pushRes = await server.inject({
				method: "POST",
				url: "/api/v1/log/push",
				headers: {
					"X-Repo-Token": hookToken,
					"Content-Type": "text/plain",
				},
				body: tamperedChain,
			});

			expect(pushRes.statusCode).toBe(422);

			// Wait briefly since webhooks are dispatched asynchronously
			await new Promise((resolve) => setTimeout(resolve, 100));

			// Assert webhook was fired
			// Note: The previous webhook might also match if we register multiple, but we look at the last one
			expect(fetchedPayloads.length).toBeGreaterThanOrEqual(1);
			const lastPayload = fetchedPayloads[fetchedPayloads.length - 1]!;

			expect(lastPayload.url).toBe("http://webhook-target.local/alert-fail");
			const options = lastPayload.options;
			expect(options.headers["X-Packablock-Signature"]).toBeDefined();

			// Parse body
			const bodyObj = JSON.parse(options.body);
			expect(bodyObj.event).toBe("push_failed_tampered");
			expect(bodyObj.repository).toBe(`${owner}/${hookRepo}`);
			expect(bodyObj.details.blockIndex).toBe(0);
			expect(bodyObj.details.tamperedComponent).toBe("data");
			expect(bodyObj.details.reason).toContain(
				"Cryptographic mismatch in data payload",
			);

			// Verify HMAC signature
			const signatureHeader = options.headers["X-Packablock-Signature"];
			const calculatedSig = crypto
				.createHmac("sha256", "fail-secret-key")
				.update(options.body)
				.digest("hex");
			expect(signatureHeader).toBe(calculatedSig);
		});
	});

	describe("Tree Visualization Endpoint", () => {
		const treeRepo = "tree-test-repo";
		let treeToken = "";

		beforeAll(async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/acme/new-account",
				payload: {
					owner,
					repo: treeRepo,
					isPremium: false,
				},
			});
			const data = JSON.parse(res.body);
			treeToken = data.registrationToken;
		});

		it("should return a correctly structured tree and graph for a multi-block chain", async () => {
			// Construct 2 blocks
			const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
				packages: {
					"package-a": { version: "1.0.0" },
				},
			});

			const block1 = createValidChainPair(1, block0.metaHash, {
				packages: {
					"package-a": { version: "1.0.0" },
					"package-b": { version: "2.0.0" },
				},
			});

			const fullChain = `${block0.chainFragment}\n${block1.chainFragment}\n`;

			// Push chain
			const pushRes = await server.inject({
				method: "POST",
				url: "/api/v1/log/push",
				headers: {
					"X-Repo-Token": treeToken,
					"Content-Type": "text/plain",
				},
				body: fullChain,
			});
			expect(pushRes.statusCode).toBe(200);

			// Call GET /tree
			const treeRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${owner}/${treeRepo}/tree`,
			});

			expect(treeRes.statusCode).toBe(200);
			const treeData = JSON.parse(treeRes.body);
			expect(treeData.success).toBe(true);
			expect(treeData.repository).toBe(`${owner}/${treeRepo}`);
			expect(treeData.blockCount).toBe(2);

			// Assert Hierarchical Tree
			expect(treeData.tree).toBeDefined();
			expect(treeData.tree.id).toBe(GENESIS_PREV_HASH);
			expect(treeData.tree.type).toBe("root");
			expect(treeData.tree.children).toHaveLength(1);

			// Assert Block 0 node
			const node0 = treeData.tree.children[0];
			expect(node0.id).toBe(block0.metaHash);
			expect(node0.name).toBe("Block #0");
			expect(node0.blockIndex).toBe(0);
			expect(node0.type).toBe("block");
			expect(node0.packagesCount).toBe(1);
			expect(node0.children).toHaveLength(1);

			// Assert Block 1 node
			const node1 = node0.children[0];
			expect(node1.id).toBe(block1.metaHash);
			expect(node1.name).toBe("Block #1");
			expect(node1.blockIndex).toBe(1);
			expect(node1.type).toBe("block");
			expect(node1.packagesCount).toBe(2);
			expect(node1.children).toHaveLength(0);

			// Assert Flat Graph structure
			expect(treeData.graph).toBeDefined();
			expect(treeData.graph.nodes).toHaveLength(3); // Root + Block 0 + Block 1
			expect(treeData.graph.links).toHaveLength(2); // Link from Root->B0, B0->B1

			// Verify flat nodes
			expect(treeData.graph.nodes[0].id).toBe(GENESIS_PREV_HASH);
			expect(treeData.graph.nodes[0].type).toBe("root");

			expect(treeData.graph.nodes[1].id).toBe(block0.metaHash);
			expect(treeData.graph.nodes[1].label).toBe("Block #0");
			expect(treeData.graph.nodes[1].type).toBe("block");

			expect(treeData.graph.nodes[2].id).toBe(block1.metaHash);
			expect(treeData.graph.nodes[2].label).toBe("Block #1");
			expect(treeData.graph.nodes[2].type).toBe("block");

			// Verify flat links
			expect(treeData.graph.links[0].source).toBe(GENESIS_PREV_HASH);
			expect(treeData.graph.links[0].target).toBe(block0.metaHash);

			expect(treeData.graph.links[1].source).toBe(block0.metaHash);
			expect(treeData.graph.links[1].target).toBe(block1.metaHash);
		});

		it("should return 404 when repository has no package history", async () => {
			const emptyRepo = "empty-tree-repo";
			await server.inject({
				method: "POST",
				url: "/api/v1/acme/new-account",
				payload: {
					owner,
					repo: emptyRepo,
					isPremium: false,
				},
			});

			const treeRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${owner}/${emptyRepo}/tree`,
			});

			expect(treeRes.statusCode).toBe(404);
		});
	});
});
