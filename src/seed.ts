#!/usr/bin/env bun
// src/seed.ts: Registry Database Seeding Tool
// Automatically populates the SQLite database with rich, realistic projects,
// repositories, and mathematically correct cryptographic block validation histories.

import { Database } from "bun:sqlite";
import path from "node:path";
import fs from "node:fs";
import { sha256, deterministicMetaHash, GENESIS_PREV_HASH } from "./verify.js";
import YAML from "yaml";

const DB_FILE =
	process.env.DATABASE_FILE ||
	path.join(process.cwd(), "data", "packablock.sqlite");

// Helper to construct mathematically correct cryptographically signed block pairs [data, meta]
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
		timestamp: new Date(Date.now() - (10 - index) * 3600 * 1000).toISOString(),
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

async function runSeeder() {
	console.log(`🌱 Initializing seeder connection to: ${DB_FILE}`);

	// Create data directory if missing
	const dbDir = path.dirname(DB_FILE);
	if (!fs.existsSync(dbDir)) {
		fs.mkdirSync(dbDir, { recursive: true });
	}

	const db = new Database(DB_FILE, { create: true });
	db.run("PRAGMA foreign_keys = ON;");

	// Clear existing tables
	console.log("🧹 Cleaning old database records...");
	db.run("DELETE FROM integration_events;");
	db.run("DELETE FROM archived_logs;");
	db.run("DELETE FROM webhooks;");
	db.run("DELETE FROM logs;");
	db.run("DELETE FROM repositories;");
	db.run("DELETE FROM projects;");

	// 1. Seed Projects
	console.log("🎯 Seeding Projects...");
	const projects = [
		{
			id: "supply-chain-defense",
			name: "Supply Chain Defense Panel",
			created_at: new Date().toISOString(),
		},
		{
			id: "ecommerce-core",
			name: "E-Commerce Core Services",
			created_at: new Date().toISOString(),
		},
	];

	const insertProject = db.prepare(
		"INSERT INTO projects (id, name, created_at) VALUES ($id, $name, $created_at)",
	);
	for (const p of projects) {
		insertProject.run({ $id: p.id, $name: p.name, $created_at: p.created_at });
	}

	// 2. Seed Repositories
	console.log("📦 Seeding Repositories...");
	const repos = [
		{
			id: 1,
			owner: "packablock",
			repo: "pblk-signer",
			registration_token: "tok_signer_123",
			created_at: new Date().toISOString(),
			is_premium: 1,
			verification_status: "verified",
			challenge_nonce: "nonce_signer_123",
			pinned_public_key:
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAR/xZWsxU3ULctSIu/K7zOzj6HPsKz09mofAGHaQArx developer@packablock.com",
			project_id: "supply-chain-defense",
		},
		{
			id: 2,
			owner: "packablock",
			repo: "pblk-auditor",
			registration_token: "tok_auditor_456",
			created_at: new Date().toISOString(),
			is_premium: 0,
			verification_status: "none",
			challenge_nonce: null,
			pinned_public_key: null,
			project_id: "supply-chain-defense",
		},
		{
			id: 3,
			owner: "acme",
			repo: "payment-gateway",
			registration_token: "tok_gateway_789",
			created_at: new Date().toISOString(),
			is_premium: 1,
			verification_status: "verified",
			challenge_nonce: "nonce_gateway_456",
			pinned_public_key:
				"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC56cK32oU9eRfG8D1aXv9Z gatekeeper@acme.com",
			project_id: "ecommerce-core",
		},
		{
			id: 4,
			owner: "acme",
			repo: "shopping-cart",
			registration_token: "tok_cart_012",
			created_at: new Date().toISOString(),
			is_premium: 0,
			verification_status: "none",
			challenge_nonce: null,
			pinned_public_key: null,
			project_id: "ecommerce-core",
		},
	];

	const insertRepo = db.prepare(`
		INSERT INTO repositories 
		(id, owner, repo, registration_token, created_at, is_premium, verification_status, challenge_nonce, pinned_public_key, project_id) 
		VALUES ($id, $owner, $repo, $registration_token, $created_at, $is_premium, $verification_status, $challenge_nonce, $pinned_public_key, $project_id)
	`);

	for (const r of repos) {
		insertRepo.run({
			$id: r.id,
			$owner: r.owner,
			$repo: r.repo,
			$registration_token: r.registration_token,
			$created_at: r.created_at,
			$is_premium: r.is_premium,
			$verification_status: r.verification_status,
			$challenge_nonce: r.challenge_nonce,
			$pinned_public_key: r.pinned_public_key,
			$project_id: r.project_id,
		});
	}

	// 3. Seed Outbound Webhooks
	console.log("🔗 Seeding Outbound Webhooks...");
	const webhooks = [
		{
			repo_id: 1,
			url: "https://discord.com/api/webhooks/packablock-audit",
			secret: "hmac_secret_key_123",
		},
		{
			repo_id: 3,
			url: "https://hooks.slack.com/services/acme-security-ops",
			secret: "hmac_secret_key_456",
		},
	];
	const insertWebhook = db.prepare(
		"INSERT INTO webhooks (repo_id, url, secret, created_at) VALUES ($repo_id, $url, $secret, $created_at)",
	);
	for (const w of webhooks) {
		insertWebhook.run({
			$repo_id: w.repo_id,
			$url: w.url,
			$secret: w.secret,
			$created_at: new Date().toISOString(),
		});
	}

	// 4. Seed Cryptographic Ledger Histories
	console.log("⛓️  Compiling cryptographic chain blocks...");

	// --- A. Ledger for 'packablock/pblk-signer' (Premium, OIDC/SSH/GPG, Rollovers) ---
	let chain1 = "";
	let prevHash1 = GENESIS_PREV_HASH;

	// Block #0 (Genesis - Epoch 0)
	const block1_0 = createValidChainPair(
		0,
		prevHash1,
		{
			name: "packablock/pblk-signer",
			version: "1.0.0",
			commit: "92ab56f",
			description: "Genesis release of pblk-signer",
		},
		{
			ssh_fingerprint: "SHA256:6iz0DBVAEGHOi6th+GYtd+t2/GoETMXrkT8V/jWa6og",
			git_actor: "developer@packablock.com",
		},
	);
	chain1 += block1_0.chainFragment;
	prevHash1 = block1_0.metaHash;

	// Block #1 (OIDC Actions - Epoch 0)
	const block1_1 = createValidChainPair(
		1,
		prevHash1,
		{
			name: "packablock/pblk-signer",
			version: "1.1.0",
			commit: "12bc34d",
			description: "Add parallel signing pipelines",
		},
		{
			oidc_claims: {
				actor: "agy-github-runner",
				repository: "Packablock/packablock-client",
				workflow: "Release Gate",
			},
			git_actor: "agy@packablock.com",
		},
	);
	chain1 += "\n" + block1_1.chainFragment;
	prevHash1 = block1_1.metaHash;

	// Block #2 (OIDC Actions - Epoch 0)
	const block1_2 = createValidChainPair(
		2,
		prevHash1,
		{
			name: "packablock/pblk-signer",
			version: "1.1.1",
			commit: "bc87d10",
			description: "Fix race condition in key buffers",
		},
		{
			oidc_claims: {
				actor: "contributor-1-github-runner",
				repository: "Packablock/packablock-client",
				workflow: "CI Lint",
			},
			git_actor: "contributor1@packablock.com",
		},
	);
	chain1 += "\n" + block1_2.chainFragment;
	const lastHashEpoch0 = block1_2.metaHash;

	// Archive Epoch 0 into archived_logs! (Demonstrating rolling archiving)
	db.run(
		`
		INSERT INTO archived_logs (repo_id, epoch_index, chain_content, block_count, last_block_hash, archived_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		[1, 0, chain1, 3, lastHashEpoch0, new Date().toISOString()],
	);

	// Block #0 (Genesis Rollover - Epoch 1)
	let chain1_epoch1 = "";
	const block1_3 = createValidChainPair(
		0,
		lastHashEpoch0,
		{
			genesis_rollover: true,
			previous_epoch: 0,
			rollover_reason: "Scheduled quarterly key rotation",
			rollover_authority: "pblk-rollover-cli",
		},
		{
			oidc_claims: { actor: "pblk-rollover-cli" },
			git_actor: "owner@packablock.com",
		},
	);
	chain1_epoch1 += block1_3.chainFragment;
	prevHash1 = block1_3.metaHash;

	// Block #1 (GPG Signed - Epoch 1)
	const block1_4 = createValidChainPair(
		1,
		prevHash1,
		{
			name: "packablock/pblk-signer",
			version: "2.0.0",
			commit: "fe29c81",
			description: "Major breaking key signature change",
		},
		{
			gpg_signature: "GPG-SIGN-256-AUTHENTIC",
			git_actor: "owner@packablock.com",
		},
	);
	chain1_epoch1 += "\n" + block1_4.chainFragment;
	const finalHash1 = block1_4.metaHash;

	// Insert active log for Repo 1
	db.run(
		`
		INSERT INTO logs (repo_id, chain_content, block_count, last_block_hash, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		[1, chain1_epoch1, 2, finalHash1, new Date().toISOString()],
	);

	// --- B. Ledger for 'packablock/pblk-auditor' (Standard Tier, Basic Blocks) ---
	let chain2 = "";
	let prevHash2 = GENESIS_PREV_HASH;

	const block2_0 = createValidChainPair(
		0,
		prevHash2,
		{
			name: "packablock/pblk-auditor",
			version: "1.0.0",
			commit: "7b89fc1",
			description: "Genesis release of pblk-auditor",
		},
		{ git_actor: "contributor1@packablock.com" },
	);
	chain2 += block2_0.chainFragment;
	prevHash2 = block2_0.metaHash;

	const block2_1 = createValidChainPair(
		1,
		prevHash2,
		{
			name: "packablock/pblk-auditor",
			version: "1.0.1",
			commit: "44ef22c",
			description: "Implement local integrity parsing",
		},
		{ git_actor: "contributor1@packablock.com" },
	);
	chain2 += "\n" + block2_1.chainFragment;
	const finalHash2 = block2_1.metaHash;

	// Insert active log for Repo 2
	db.run(
		`
		INSERT INTO logs (repo_id, chain_content, block_count, last_block_hash, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		[2, chain2, 2, finalHash2, new Date().toISOString()],
	);

	// --- C. Ledger for 'acme/payment-gateway' (Premium, OIDC/SSH Verification) ---
	let chain3 = "";
	let prevHash3 = GENESIS_PREV_HASH;

	const block3_0 = createValidChainPair(
		0,
		prevHash3,
		{
			name: "acme/payment-gateway",
			version: "1.0.0",
			commit: "0a1b2c3",
			description: "Genesis ACME payment handler",
		},
		{
			ssh_fingerprint: "SHA256:IC56cK32oU9eRfG8D1aXv9Z",
			git_actor: "gatekeeper@acme.com",
		},
	);
	chain3 += block3_0.chainFragment;
	prevHash3 = block3_0.metaHash;

	const block3_1 = createValidChainPair(
		1,
		prevHash3,
		{
			name: "acme/payment-gateway",
			version: "1.1.0",
			commit: "88abcf2",
			description: "Secure tokenization pipeline integration",
		},
		{
			oidc_claims: {
				actor: "acme-jenkins-runner",
				repository: "acme/payment-gateway",
				workflow: "Prod Deployment",
			},
			git_actor: "gatekeeper@acme.com",
		},
	);
	chain3 += "\n" + block3_1.chainFragment;
	const finalHash3 = block3_1.metaHash;

	// Insert active log for Repo 3
	db.run(
		`
		INSERT INTO logs (repo_id, chain_content, block_count, last_block_hash, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		[3, chain3, 2, finalHash3, new Date().toISOString()],
	);

	// --- D. Ledger for 'acme/shopping-cart' (Standard, Basic Timeline) ---
	let chain4 = "";
	let prevHash4 = GENESIS_PREV_HASH;

	const block4_0 = createValidChainPair(
		0,
		prevHash4,
		{
			name: "acme/shopping-cart",
			version: "1.0.0",
			commit: "fe77ab2",
			description: "Genesis ACME checkout cart",
		},
		{ git_actor: "checkout-lead@acme.com" },
	);
	chain4 += block4_0.chainFragment;
	const finalHash4 = block4_0.metaHash;

	// Insert active log for Repo 4
	db.run(
		`
		INSERT INTO logs (repo_id, chain_content, block_count, last_block_hash, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`,
		[4, chain4, 1, finalHash4, new Date().toISOString()],
	);

	// 5. Seed Integration Events Dashboard logs
	console.log("📊 Seeding dashboard Integration Events logs...");
	const integrationEvents = [
		{
			repo_id: 1,
			client_version: "1.0.1",
			os_platform: "linux",
			runtime_env: "bun/1.0.5",
			is_ci: 1,
			client_ip: "10.0.4.12",
			git_actor: "Agy",
		},
		{
			repo_id: 1,
			client_version: "1.0.1",
			os_platform: "darwin",
			runtime_env: "node/v18.16.0",
			is_ci: 0,
			client_ip: "192.168.1.45",
			git_actor: "Aaron Bronow",
		},
		{
			repo_id: 3,
			client_version: "1.0.1",
			os_platform: "linux",
			runtime_env: "bun/1.0.5",
			is_ci: 1,
			client_ip: "10.0.12.80",
			git_actor: "acme-jenkins-runner",
		},
	];

	const insertEvent = db.prepare(`
		INSERT INTO integration_events 
		(repo_id, client_version, os_platform, runtime_env, is_ci, client_ip, git_actor, created_at)
		VALUES ($repo_id, $client_version, $os_platform, $runtime_env, $is_ci, $client_ip, $git_actor, $created_at)
	`);

	for (const e of integrationEvents) {
		insertEvent.run({
			$repo_id: e.repo_id,
			$client_version: e.client_version,
			$os_platform: e.os_platform,
			$runtime_env: e.runtime_env,
			$is_ci: e.is_ci,
			$client_ip: e.client_ip,
			$git_actor: e.git_actor,
			$created_at: new Date(Date.now() - 3600 * 1000).toISOString(),
		});
	}

	db.close();
	console.log(
		"🎉 SQLite Database seeded successfully with realistic projects, repos, and complex histories!",
	);
}

runSeeder().catch((err) => {
	console.error("❌ Failed to seed database:", err);
	process.exit(1);
});
