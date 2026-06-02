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

const TEST_DB = "packablock_test_issue4.sqlite";

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

describe("Issue #4 - New Registry API Endpoints", () => {
	const owner = "issue4owner";
	const repoName = "issue4-repo";
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

	describe("GET /api/v1/repo/:id/history & GET /api/v1/repo/:id/sigs", () => {
		it("should return 404 when repository has no package history", async () => {
			const resHistory = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${repoId}/history`,
			});
			expect(resHistory.statusCode).toBe(404);

			const resSigs = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${repoId}/sigs`,
			});
			expect(resSigs.statusCode).toBe(404);
		});

		it("should return 404 for a non-existent repository ID", async () => {
			const resHistory = await server.inject({
				method: "GET",
				url: "/api/v1/repo/99999/history",
			});
			expect(resHistory.statusCode).toBe(404);

			const resSigs = await server.inject({
				method: "GET",
				url: "/api/v1/repo/99999/sigs",
			});
			expect(resSigs.statusCode).toBe(404);
		});

		it("should return chronological list of blocks and signatures after successful push", async () => {
			// Construct Block 0 (Genesis)
			const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
				packages: {
					"package-x": {
						version: "1.0.0",
						integrity: "sha512-xGenesis",
					},
				},
			});

			// Construct Block 1 with custom signature & actor claims
			const block1 = createValidChainPair(
				1,
				block0.metaHash,
				{
					packages: {
						"package-x": {
							version: "1.0.1",
							integrity: "sha512-xBumped",
						},
					},
				},
				{
					committer: "Aaron Bronow",
					signature: "gpg-sig-abc",
					ssh_fingerprint: "SHA256:abc123ssh",
					gpg_signature: "GPG-ABC-123",
					git_actor: "aaron-github-actor",
					oidc_claims: {
						actor: "aaron-ci-actor",
						workflow: "issue4.yml",
					},
				},
			);

			const fullChain = `${block0.chainFragment}\n${block1.chainFragment}\n`;

			const pushRes = await server.inject({
				method: "POST",
				url: "/api/v1/log/push",
				headers: {
					"X-Repo-Token": registrationToken,
					"Content-Type": "text/plain",
				},
				body: fullChain,
			});
			expect(pushRes.statusCode).toBe(200);

			// Test GET /api/v1/repo/:id/history
			const historyRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${repoId}/history`,
			});
			expect(historyRes.statusCode).toBe(200);
			const history = JSON.parse(historyRes.body);
			expect(history).toBeArray();
			expect(history).toHaveLength(2);

			// Assert Block 0 history payload
			expect(history[0].block_index).toBe(0);
			expect(history[0].prev_meta_hash).toBe(GENESIS_PREV_HASH);
			expect(history[0].data_hash).toBe(block0.dataHash);
			expect(history[0].meta_hash).toBe(block0.metaHash);
			expect(history[0].packages["package-x"].version).toBe("1.0.0");

			// Assert Block 1 history payload
			expect(history[1].block_index).toBe(1);
			expect(history[1].prev_meta_hash).toBe(block0.metaHash);
			expect(history[1].data_hash).toBe(block1.dataHash);
			expect(history[1].meta_hash).toBe(block1.metaHash);
			expect(history[1].packages["package-x"].version).toBe("1.0.1");

			// Test GET /api/v1/repo/:id/sigs
			const sigsRes = await server.inject({
				method: "GET",
				url: `/api/v1/repo/${repoId}/sigs`,
			});
			expect(sigsRes.statusCode).toBe(200);
			const sigs = JSON.parse(sigsRes.body);
			expect(sigs).toBeArray();
			expect(sigs).toHaveLength(2);

			// Assert Block 0 signatures
			expect(sigs[0].blockIndex).toBe(0);
			expect(sigs[0].committer).toBeNull();
			expect(sigs[0].signature).toBeNull();
			expect(sigs[0].oidcClaims).toBeNull();

			// Assert Block 1 signatures
			expect(sigs[1].blockIndex).toBe(1);
			expect(sigs[1].committer).toBe("Aaron Bronow");
			expect(sigs[1].signature).toBe("gpg-sig-abc");
			expect(sigs[1].oidcClaims.actor).toBe("aaron-ci-actor");
			expect(sigs[1].sshFingerprint).toBe("SHA256:abc123ssh");
			expect(sigs[1].gpgSignature).toBe("GPG-ABC-123");
			expect(sigs[1].gitActor).toBe("aaron-github-actor");
		});
	});

	describe("POST /api/v1/alerts (Webhook Registry)", () => {
		it("should reject webhook with missing fields", async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/alerts",
				payload: {
					url: "http://outbound.webhook/alert",
				},
			});
			expect(res.statusCode).toBe(400);
		});

		it("should reject webhook with invalid repo_id format", async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/alerts",
				payload: {
					repo_id: "not-a-number",
					url: "http://outbound.webhook/alert",
				},
			});
			expect(res.statusCode).toBe(400);
		});

		it("should return 404 for a non-existent repo_id", async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/alerts",
				payload: {
					repo_id: 99999,
					url: "http://outbound.webhook/alert",
				},
			});
			expect(res.statusCode).toBe(404);
		});

		it("should successfully register a webhook and return 201 with details", async () => {
			const res = await server.inject({
				method: "POST",
				url: "/api/v1/alerts",
				payload: {
					repo_id: repoId,
					url: "http://outbound.webhook/alert",
					secret: "alert-secret-key",
				},
			});

			expect(res.statusCode).toBe(201);
			const webhook = JSON.parse(res.body);
			expect(webhook.id).toBeDefined();
			expect(webhook.repo_id).toBe(repoId);
			expect(webhook.url).toBe("http://outbound.webhook/alert");
			expect(webhook.secret).toBe("alert-secret-key");
			expect(webhook.created_at).toBeDefined();
		});
	});
});
