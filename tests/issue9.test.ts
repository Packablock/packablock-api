import {
	describe,
	it,
	expect,
	beforeAll,
	afterAll,
	beforeEach,
} from "bun:test";
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
import crypto from "node:crypto";

const TEST_DB = "packablock_test_issue9.sqlite";

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

describe("Issue #9 - SemVer-based alerting & webhook triggers on registry push events", () => {
	const owner = "issue9owner";
	const repoName = "issue9-repo";
	let repoId = 0;
	let registrationToken = "";
	let fetchedPayloads: Array<{ url: string; options: any }> = [];

	beforeAll(async () => {
		// Register a test repo
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
		repoId = repoRecord!.id;

		// Register a webhook
		const registerWebhookRes = await server.inject({
			method: "POST",
			url: `/api/v1/repo/${owner}/${repoName}/webhooks`,
			payload: {
				url: "http://webhook-target.local/issue9-alert",
				secret: "issue9-secret-key",
			},
		});
		expect(registerWebhookRes.statusCode).toBe(200);
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

	it("should trigger correct SemVer webhooks (chain.pushed, package.added, health.warning open_fuse_rule) on first block push", async () => {
		// Block 0: foo (1.0.0), bar (>=2.0.0) -> triggers open fuse constraint warning
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			"package-lock.json": {
				packages: [
					{ foo: "1.0.0" },
					{ bar: ">=2.0.0" },
				],
			},
		});

		const fullChain = `${block0.chainFragment}\n`;

		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": registrationToken,
				"Content-Type": "text/plain",
				"X-Client-Actor": "github-actions-contributor-1",
			},
			body: fullChain,
		});

		expect(pushRes.statusCode).toBe(200);

		// Wait briefly since webhooks are dispatched asynchronously
		await new Promise((resolve) => setTimeout(resolve, 100));

		// We expect:
		// 1. push_success
		// 2. chain.pushed
		// 3. package.added (foo)
		// 4. package.added (bar)
		// 5. health.warning (bar - open_fuse_rule)
		const events = fetchedPayloads.map((p) => JSON.parse(p.options.body).event);
		expect(events).toContain("push_success");
		expect(events).toContain("chain.pushed");
		expect(events).toContain("package.added");
		expect(events).toContain("health.warning");

		// Assert chain.pushed event payload
		const chainPushedPayload = fetchedPayloads.find(
			(p) => JSON.parse(p.options.body).event === "chain.pushed",
		);
		expect(chainPushedPayload).toBeDefined();
		const cpBody = JSON.parse(chainPushedPayload!.options.body);
		expect(cpBody.details.blockIndex).toBe(0);
		expect(cpBody.details.version).toBe("1.0.0");
		expect(cpBody.details.metaHash).toBe(block0.metaHash);
		expect(cpBody.details.actor).toBe("github-actions-contributor-1");

		// Assert package.added events
		const packageAddedPayloads = fetchedPayloads.filter(
			(p) => JSON.parse(p.options.body).event === "package.added",
		);
		expect(packageAddedPayloads).toHaveLength(2);
		const pkgAddedNames = packageAddedPayloads.map(
			(p) => JSON.parse(p.options.body).details.package,
		);
		expect(pkgAddedNames).toContain("foo");
		expect(pkgAddedNames).toContain("bar");

		const barAdded = packageAddedPayloads.find(
			(p) => JSON.parse(p.options.body).details.package === "bar",
		);
		expect(JSON.parse(barAdded!.options.body).details.version).toBe(">=2.0.0");

		// Assert open fuse rule health warning
		const healthWarningPayloads = fetchedPayloads.filter(
			(p) => JSON.parse(p.options.body).event === "health.warning",
		);
		expect(healthWarningPayloads).toHaveLength(1);
		const warningBody = JSON.parse(healthWarningPayloads[0]!.options.body);
		expect(warningBody.details.package).toBe("bar");
		expect(warningBody.details.warningType).toBe("open_fuse_rule");
		expect(warningBody.details.severity).toBe("critical");
	});

	it("should trigger technical_debt_wall health warning and package.updated on second block push with major version bump", async () => {
		// Build a chain that contains block0 + block1
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			"package-lock.json": {
				packages: [
					{ foo: "1.0.0" },
					{ bar: ">=2.0.0" },
				],
			},
		});

		// Block 1: foo (2.0.0 - major upgrade), bar (2.1.0 - update), baz (3.0.0 - added)
		const block1 = createValidChainPair(1, block0.metaHash, {
			"package-lock.json": {
				packages: [
					{ foo: [{ old: "1.0.0" }, { new: "2.0.0" }] },
					{ bar: [{ old: ">=2.0.0" }, { new: "2.1.0" }] },
					{ baz: [{ new: "3.0.0" }] },
				],
			},
		});

		const fullChain = `${block0.chainFragment}\n${block1.chainFragment}\n`;

		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": registrationToken,
				"Content-Type": "text/plain",
				"X-Client-Actor": "github-actions-contributor-1",
			},
			body: fullChain,
		});

		expect(pushRes.statusCode).toBe(200);

		// Wait briefly since webhooks are dispatched asynchronously
		await new Promise((resolve) => setTimeout(resolve, 100));

		const events = fetchedPayloads.map((p) => JSON.parse(p.options.body).event);
		expect(events).toContain("chain.pushed");
		expect(events).toContain("package.updated");
		expect(events).toContain("package.added");

		// Assert package.updated events (foo, bar)
		const packageUpdatedPayloads = fetchedPayloads.filter(
			(p) => JSON.parse(p.options.body).event === "package.updated",
		);
		expect(packageUpdatedPayloads).toHaveLength(2);
		const pkgUpdatedNames = packageUpdatedPayloads.map(
			(p) => JSON.parse(p.options.body).details.package,
		);
		expect(pkgUpdatedNames).toContain("foo");
		expect(pkgUpdatedNames).toContain("bar");

		const fooUpdated = packageUpdatedPayloads.find(
			(p) => JSON.parse(p.options.body).details.package === "foo",
		);
		const fooUpdateBody = JSON.parse(fooUpdated!.options.body).details;
		expect(fooUpdateBody.oldVersion).toBe("1.0.0");
		expect(fooUpdateBody.newVersion).toBe("2.0.0");

		// Assert technical debt wall warning on foo (1.0.0 -> 2.0.0)
		const healthWarningPayloads = fetchedPayloads.filter(
			(p) => JSON.parse(p.options.body).event === "health.warning",
		);
		expect(healthWarningPayloads).toHaveLength(1);
		const warningBody = JSON.parse(healthWarningPayloads[0]!.options.body);
		expect(warningBody.details.package).toBe("foo");
		expect(warningBody.details.warningType).toBe("technical_debt_wall");
		expect(warningBody.details.severity).toBe("warning");

		// Assert package.added on baz (3.0.0)
		const packageAddedPayloads = fetchedPayloads.filter(
			(p) => JSON.parse(p.options.body).event === "package.added",
		);
		expect(packageAddedPayloads).toHaveLength(1);
		expect(
			JSON.parse(packageAddedPayloads[0]!.options.body).details.package,
		).toBe("baz");
	});

	it("should trigger dependency_regression and high_drift_velocity health warnings on third block push", async () => {
		const block0 = createValidChainPair(0, GENESIS_PREV_HASH, {
			"package-lock.json": {
				packages: [
					{ foo: "1.0.0" },
					{ bar: ">=2.0.0" },
				],
			},
		});

		const block1 = createValidChainPair(1, block0.metaHash, {
			"package-lock.json": {
				packages: [
					{ foo: [{ old: "1.0.0" }, { new: "2.0.0" }] },
					{ bar: [{ old: ">=2.0.0" }, { new: "2.1.0" }] },
					{ baz: [{ new: "3.0.0" }] },
				],
			},
		});

		const block2 = createValidChainPair(2, block1.metaHash, {
			"package-lock.json": {
				packages: [
					{ foo: [{ old: "2.0.0" }, { new: "1.8.0" }] },
					{ baz: [{ old: "3.0.0" }, { new: "3.4.0" }] },
				],
			},
		});

		const fullChain = `${block0.chainFragment}\n${block1.chainFragment}\n${block2.chainFragment}\n`;

		const pushRes = await server.inject({
			method: "POST",
			url: "/api/v1/log/push",
			headers: {
				"X-Repo-Token": registrationToken,
				"Content-Type": "text/plain",
				"X-Client-Actor": "github-actions-contributor-1",
			},
			body: fullChain,
		});

		expect(pushRes.statusCode).toBe(200);

		// Wait briefly since webhooks are dispatched asynchronously
		await new Promise((resolve) => setTimeout(resolve, 100));

		const events = fetchedPayloads.map((p) => JSON.parse(p.options.body).event);
		expect(events).toContain("chain.pushed");
		expect(events).toContain("package.updated");
		expect(events).toContain("health.warning");

		// Assert health warnings
		const healthWarningPayloads = fetchedPayloads.filter(
			(p) => JSON.parse(p.options.body).event === "health.warning",
		);
		expect(healthWarningPayloads).toHaveLength(2);

		const regressionWarning = healthWarningPayloads.find(
			(p) =>
				JSON.parse(p.options.body).details.warningType ===
				"dependency_regression",
		);
		expect(regressionWarning).toBeDefined();
		const regBody = JSON.parse(regressionWarning!.options.body).details;
		expect(regBody.package).toBe("foo");
		expect(regBody.severity).toBe("critical");

		const driftWarning = healthWarningPayloads.find(
			(p) =>
				JSON.parse(p.options.body).details.warningType ===
				"high_drift_velocity",
		);
		expect(driftWarning).toBeDefined();
		const driftBody = JSON.parse(driftWarning!.options.body).details;
		expect(driftBody.package).toBe("baz");
		expect(driftBody.severity).toBe("warning");
	});
});
