import { describe, expect, it, beforeEach, afterEach } from "bun:test";
import { server } from "../src/server.js";
import { initDb, registerRepository } from "../src/database.js";
import {
	sha256,
	deterministicMetaHash,
	GENESIS_PREV_HASH,
} from "../src/verify.js";
import fs from "node:fs/promises";
import path from "node:path";
import { Database } from "bun:sqlite";
import YAML from "yaml";

function createValidChainPair(
	index: number,
	prevMetaHash: string,
	dataObj: any,
	metaExtra: any = {},
) {
	let finalDataObj = dataObj;
	if (
		dataObj &&
		typeof dataObj === "object" &&
		!("lockfiles" in dataObj) &&
		!("genesis_rollover" in dataObj)
	) {
		finalDataObj = { lockfiles: dataObj };
	}
	const dataDocStr = YAML.stringify(finalDataObj);
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

describe("Registry Server-Side Security & Integrity Gates", () => {
	const owner = "securityowner";
	const repo = "security-repo";
	const token = "pb_reg_security_test_token_888";
	const dbFile = "packablock_test_security.sqlite";

	beforeEach(async () => {
		process.env.DATABASE_FILE = dbFile;
		initDb();
		registerRepository(owner, repo, token);
	});

	afterEach(async () => {
		try {
			await fs.unlink(path.join(process.cwd(), dbFile));
		} catch (e) {}
	});

	it("should reject a push with a tampered data payload hash", async () => {
		// Construct Block 0
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			"package-lock.json": { packages: [{ "packa-block": "1.0.0" }] },
		});

		// Tamper with the data payload, so it doesn't match the data_hash in metadata
		const tamperedDataDocStr = block0.dataDocStr.replace("1.0.0", "9.9.9");
		const tamperedPayload = `---\n${tamperedDataDocStr}---\n${block0.metaDocStr}\n`;

		const res = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/plain",
				"x-repo-token": token,
			},
			body: tamperedPayload,
		});

		expect(res.statusCode).toBe(422);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Unprocessable Entity");
		expect(data.message).toBe("Chain cryptographic verification failed.");
		expect(data.details.reason).toContain(
			"Cryptographic mismatch in data payload",
		);
	});

	it("should reject a push with a tampered metadata block hash", async () => {
		// Construct Block 0 manually with a mismatching meta_hash
		const dataDocStr = YAML.stringify({
			lockfiles: {
				"package-lock.json": { packages: [{ "packa-block": "1.0.0" }] },
			},
		});
		const dataHash = sha256(dataDocStr.trim());

		const metaObj = {
			version: "1.0.0",
			block_index: 0,
			timestamp: new Date().toISOString(),
			hashing_strategy: "raw" as const,
			data_hash: dataHash,
			prev_meta_hash: GENESIS_PREV_HASH,
			meta_hash: "invalid-meta-hash-signature-12345",
		};

		const metaDocStr = YAML.stringify({ "$yaml-chain-meta": metaObj });
		const tamperedPayload = `---\n${dataDocStr}---\n${metaDocStr}\n`;

		const res = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/plain",
				"x-repo-token": token,
			},
			body: tamperedPayload,
		});

		expect(res.statusCode).toBe(422);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Unprocessable Entity");
		expect(data.message).toBe("Chain cryptographic verification failed.");
		expect(data.details.reason).toContain(
			"Cryptographic mismatch in metadata signature itself",
		);
	});

	it("should reject a push with a broken chain link (prev_meta_hash mismatch)", async () => {
		// Construct Block 0
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			"package-lock.json": { packages: [{ "packa-block": "1.0.0" }] },
		});

		// Construct Block 1 with wrong prev_meta_hash
		const block1 = createValidChainPair(1, "mismatched-prev-meta-hash-value", {
			"package-lock.json": {
				packages: [
					{
						"packa-block": [{ old: "1.0.0" }, { new: "1.1.0" }],
					},
				],
			},
		});

		const payload = `${block0.chainFragment}\n${block1.chainFragment}\n`;

		const res = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"content-type": "text/plain",
				"x-repo-token": token,
			},
			body: payload,
		});

		expect(res.statusCode).toBe(422);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Unprocessable Entity");
		expect(data.message).toBe("Chain cryptographic verification failed.");
		expect(data.details.reason).toContain("Chain link broken at block 1");
	});

	describe("Administrative Endpoints Auth Gates", () => {
		const internalToken = "my_super_secret_test_token_9876";

		beforeEach(() => {
			process.env.INTERNAL_REGISTRY_TOKEN = internalToken;
		});

		it("should reject internal status requests without internal token", async () => {
			const res = await server.inject({
				method: "GET",
				url: "/api/v1/internal/system/status",
			});
			expect(res.statusCode).toBe(401);
			const data = JSON.parse(res.body);
			expect(data.error).toBe("Unauthorized");
		});

		it("should reject internal repos requests with invalid token", async () => {
			const res = await server.inject({
				method: "GET",
				url: "/api/v1/internal/repos",
				headers: {
					"x-packablock-internal-token": "wrong-token",
				},
			});
			expect(res.statusCode).toBe(401);
		});

		it("should allow internal status requests with valid internal token", async () => {
			const res = await server.inject({
				method: "GET",
				url: "/api/v1/internal/system/status",
				headers: {
					"x-packablock-internal-token": internalToken,
				},
			});
			expect(res.statusCode).toBe(200);
			const data = JSON.parse(res.body);
			expect(data.success).toBe(true);
			expect(data.status).toBe("Secured");
		});

		it("should allow list of repos and purge-stale when authorized", async () => {
			const resList = await server.inject({
				method: "GET",
				url: "/api/v1/internal/repos",
				headers: {
					"x-packablock-internal-token": internalToken,
				},
			});
			expect(resList.statusCode).toBe(200);

			const resPurge = await server.inject({
				method: "POST",
				url: "/api/v1/internal/purge-stale",
				headers: {
					"x-packablock-internal-token": internalToken,
				},
			});
			expect(resPurge.statusCode).toBe(200);
			const data = JSON.parse(resPurge.body);
			expect(data.success).toBe(true);
			expect(data.purgedCount).toBeDefined();
		});
	});

	describe("Database Schema Migrations", () => {
		const migrationDbFile = "packablock_test_migration.sqlite";

		afterEach(async () => {
			try {
				await fs.unlink(path.join(process.cwd(), migrationDbFile));
			} catch (e) {}
		});

		it("should successfully migrate a legacy schema database missing modern columns", async () => {
			const dbPath = path.join(process.cwd(), migrationDbFile);

			// 1. Create a legacy database file with an older repositories table schema
			const legacyDb = new Database(dbPath, { create: true });
			legacyDb.run(`
				CREATE TABLE repositories (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					owner TEXT NOT NULL,
					repo TEXT NOT NULL,
					registration_token TEXT UNIQUE NOT NULL,
					created_at TEXT NOT NULL,
					UNIQUE(owner, repo)
				);
			`);
			legacyDb.run(`
				INSERT INTO repositories (owner, repo, registration_token, created_at)
				VALUES ('oldowner', 'oldrepo', 'pb_old_token_123', '2023-01-01T00:00:00Z');
			`);
			legacyDb.close();

			// 2. Point process.env.DATABASE_FILE to our legacy DB and initialize
			process.env.DATABASE_FILE = migrationDbFile;

			// Calling initDb should trigger the try-catch migration blocks inside initDb
			expect(() => initDb()).not.toThrow();

			// 3. Verify that the migrated columns exist and can be read / written
			const migratedDb = new Database(dbPath);
			const row = migratedDb
				.prepare("SELECT * FROM repositories WHERE owner = 'oldowner'")
				.get() as any;

			// Check if migrated columns were added and defaulted appropriately
			expect(row.is_premium).toBe(0);
			expect(row.verification_status).toBe("none");
			expect(row.challenge_nonce).toBeNull();
			expect(row.pinned_public_key).toBeNull();
			expect(row.project_id).toBeNull();

			// Test writing to the new columns on the migrated database
			expect(() => {
				migratedDb.run(
					"UPDATE repositories SET is_premium = 1, verification_status = 'verified' WHERE id = ?",
					[row.id],
				);
			}).not.toThrow();

			const updatedRow = migratedDb
				.prepare("SELECT * FROM repositories WHERE owner = 'oldowner'")
				.get() as any;
			expect(updatedRow.is_premium).toBe(1);
			expect(updatedRow.verification_status).toBe("verified");

			migratedDb.close();
		});
	});
});
