import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { server } from "../src/server.ts";
import { initDb } from "../src/database.ts";
import { sha256, deterministicMetaHash, GENESIS_PREV_HASH } from "../src/verify.ts";
import YAML from "yaml";
import fs from "node:fs";
import path from "node:path";

const TEST_DB = "packablock_test_dashboard.sqlite";
const ADMIN_TOKEN = "admin_secret_token_1234";

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
		timestamp: new Date().toISOString(),
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
	process.env.ADMIN_TOKEN = ADMIN_TOKEN;

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

describe("Registry Admin Dashboard & Projects API Endpoints", () => {
	let repoId: number;
	let projectId: string;
	let registrationToken: string;

	it("should successfully register a standard account for testing", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/acme/new-account",
			payload: {
				owner: "dashowner",
				repo: "dash-repo",
				isPremium: false,
			},
		});

		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data.success).toBe(true);
		registrationToken = data.registrationToken;
		expect(registrationToken).toBeDefined();
	});

	it("should reject admin API calls without valid authentication session", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/api/v1/admin/projects",
		});
		expect(res.statusCode).toBe(401);
		const data = JSON.parse(res.body);
		expect(data.error).toBe("Unauthorized");
	});

	it("should successfully authorize login with correct admin token", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/admin/login",
			payload: { token: ADMIN_TOKEN },
		});
		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data.success).toBe(true);
	});

	it("should reject login with incorrect admin token", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/admin/login",
			payload: { token: "forged_token" },
		});
		expect(res.statusCode).toBe(401);
	});

	it("should successfully create a new logical project container", async () => {
		const res = await server.inject({
			method: "POST",
			url: "/api/v1/admin/projects",
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
			payload: { name: "Billing Infrastructure" },
		});

		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data.success).toBe(true);
		expect(data.project.name).toBe("Billing Infrastructure");
		expect(data.project.id).toBeDefined();
		projectId = data.project.id;
	});

	it("should successfully list projects containing our new creation", async () => {
		const res = await server.inject({
			method: "GET",
			url: "/api/v1/admin/projects",
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});

		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data.success).toBe(true);
		expect(data.projects.length).toBe(1);
		expect(data.projects[0].name).toBe("Billing Infrastructure");
		expect(data.projects[0].repoCount).toBe(0);
	});

	it("should link our standard repository to our new project container", async () => {
		// First fetch the repository ID
		const reposRes = await server.inject({
			method: "GET",
			url: "/api/v1/admin/repos",
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});
		const reposData = JSON.parse(reposRes.body);
		expect(reposData.repos.length).toBe(1);
		repoId = reposData.repos[0].id;

		// Link it
		const linkRes = await server.inject({
			method: "POST",
			url: "/api/v1/admin/projects/link",
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
			payload: {
				repoId: repoId,
				projectId: projectId,
			},
		});

		expect(linkRes.statusCode).toBe(200);
		const linkData = JSON.parse(linkRes.body);
		expect(linkData.success).toBe(true);
	});

	it("should correctly list linked repos inside project checks endpoint", async () => {
		const res = await server.inject({
			method: "GET",
			url: `/api/v1/admin/projects/${projectId}/checks`,
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});

		expect(res.statusCode).toBe(200);
		const data = JSON.parse(res.body);
		expect(data.success).toBe(true);
		expect(data.repos.length).toBe(1);
		expect(data.repos[0].owner).toBe("dashowner");
		expect(data.repos[0].repo).toBe("dash-repo");
		expect(data.repos[0].project_id).toBe(projectId);
	});

	it("should record and list push integration events containing metadata headers", async () => {
		// Mock a push with metadata headers using our cryptographic helper
		const block = createValidChainPair(0, GENESIS_PREV_HASH, { message: "Initial block" });
		const mockChain = block.chainFragment + "\n";

		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"Content-Type": "text/yaml",
				"X-Repo-Token": registrationToken,
				"X-Client-Version": "1.0.1",
				"X-Client-OS": "darwin",
				"X-Client-Env": "Docker",
				"X-Client-CI": "true",
				"X-Client-Actor": "test-developer",
			},
			payload: mockChain,
		});

		expect(pushRes.statusCode).toBe(200);

		// Now query integrations audit log
		const auditRes = await server.inject({
			method: "GET",
			url: `/api/v1/admin/projects/${projectId}/integrations`,
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});

		expect(auditRes.statusCode).toBe(200);
		const auditData = JSON.parse(auditRes.body);
		expect(auditData.success).toBe(true);
		expect(auditData.events.length).toBe(1);
		expect(auditData.events[0].client_version).toBe("1.0.1");
		expect(auditData.events[0].os_platform).toBe("darwin");
		expect(auditData.events[0].runtime_env).toBe("Docker");
		expect(auditData.events[0].is_ci).toBe(1);
		expect(auditData.events[0].git_actor).toBe("test-developer");
	});

	it("should toggle premium access tier via admin API", async () => {
		const toggleRes = await server.inject({
			method: "POST",
			url: `/api/v1/admin/repo/${repoId}/toggle-premium`,
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});
		expect(toggleRes.statusCode).toBe(200);

		// Verify change
		const checkRes = await server.inject({
			method: "GET",
			url: `/api/v1/admin/projects/${projectId}/checks`,
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});
		const checkData = JSON.parse(checkRes.body);
		expect(checkData.repos[0].is_premium).toBe(1);
	});

	it("should revoke repository registration token via admin API", async () => {
		const revokeRes = await server.inject({
			method: "POST",
			url: `/api/v1/admin/repo/${repoId}/revoke`,
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});
		expect(revokeRes.statusCode).toBe(200);

		// Verify token was revoked (starts with pb_revoked_)
		const checkRes = await server.inject({
			method: "GET",
			url: `/api/v1/admin/projects/${projectId}/checks`,
			headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
		});
		const checkData = JSON.parse(checkRes.body);
		expect(checkData.repos[0].registration_token.startsWith("pb_revoked_")).toBe(true);
	});
});
