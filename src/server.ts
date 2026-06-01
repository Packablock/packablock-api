import fastify from "fastify";
import { randomBytes } from "node:crypto";
import YAML from "yaml";
import {
	initDb,
	registerRepository,
	getRepositoryByToken,
	getRepositoryByPath,
	saveLog,
	getLog,
	registerPremiumPending,
	verifyAndActivateRepository,
	addWebhook,
	getWebhooks,
	deleteWebhook,
} from "./database.js";
import { verifyInMemoryChain, splitRawDocuments } from "./verify.js";
import { verifyGithubOidcToken } from "./oidc.js";

export const server = fastify({ logger: true });

// Register content type parser for plain text / YAML payloads
server.addContentTypeParser(
	["text/yaml", "application/yaml", "text/plain"],
	{ parseAs: "string" },
	function (req, body, done) {
		done(null, body);
	},
);

/**
 * Health check endpoint
 */
server.get("/health", async () => {
	return { status: "ok", service: "packablock-registry" };
});

/**
 * Register a new repository. Returns a registration token.
 */
server.post("/api/v1/repos/register", async (request, reply) => {
	const body = request.body as any;
	if (!body || !body.owner || !body.repo) {
		return reply.status(400).send({
			error: "Bad Request",
			message: 'Fields "owner" and "repo" are required in request body.',
		});
	}

	const { owner, repo } = body;

	// Generate a cryptographically secure random registration token
	const token = "pb_reg_" + randomBytes(24).toString("hex");

	try {
		const record = registerRepository(owner, repo, token);
		return {
			success: true,
			owner: record.owner,
			repo: record.repo,
			registrationToken: record.registration_token,
			message:
				"Repository registered successfully. Store this token in your secrets!",
		};
	} catch (err: any) {
		request.log.error(err);
		return reply.status(500).send({
			error: "Internal Server Error",
			message: err.message,
		});
	}
});

/**
 * ACME-style registration for Zero-Trust premium or standard onboarding.
 */
server.post("/api/v1/acme/new-account", async (request, reply) => {
	const body = request.body as any;
	if (!body || !body.owner || !body.repo) {
		return reply.status(400).send({
			error: "Bad Request",
			message: 'Fields "owner" and "repo" are required in request body.',
		});
	}

	const { owner, repo, isPremium } = body;

	// Generate random nonce challenge
	const nonce = "pb_nonce_" + randomBytes(24).toString("hex");

	// A temporary token which remains inactive until verified
	const tempToken = "pb_temp_" + randomBytes(24).toString("hex");

	try {
		if (isPremium) {
			const record = registerPremiumPending(owner, repo, nonce, tempToken);
			return {
				success: true,
				owner: record.owner,
				repo: record.repo,
				isPremium: true,
				verificationStatus: record.verification_status,
				challengeNonce: record.challenge_nonce,
				message:
					'Premium registration initiated. Place the challengeNonce in your repository at "/.well-known/sbom-challenge/token.txt" and call verify.',
			};
		} else {
			// Standard registration (direct active token)
			const record = registerRepository(
				owner,
				repo,
				tempToken.replace("pb_temp_", "pb_reg_"),
			);
			return {
				success: true,
				owner: record.owner,
				repo: record.repo,
				isPremium: false,
				verificationStatus: "none",
				registrationToken: record.registration_token,
				message: "Standard repository registered successfully.",
			};
		}
	} catch (err: any) {
		request.log.error(err);
		return reply.status(500).send({
			error: "Internal Server Error",
			message: err.message,
		});
	}
});

/**
 * ACME-style challenge verification endpoint.
 * Supports standard GitHub API micro-verifier and Sigstore Artifact Attestations bundle validation.
 */
server.post("/api/v1/acme/verify", async (request, reply) => {
	const body = request.body as any;
	if (!body || !body.owner || !body.repo || !body.verificationType) {
		return reply.status(400).send({
			error: "Bad Request",
			message: 'Fields "owner", "repo", and "verificationType" are required.',
		});
	}

	const { owner, repo, verificationType, attestationBundle } = body;

	// Fetch pending registration details
	const record = getRepositoryByPath(owner, repo);
	if (
		!record ||
		record.is_premium === 0 ||
		record.verification_status !== "pending"
	) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No pending premium registration found for this repository.",
		});
	}

	const expectedNonce = record.challenge_nonce;
	if (!expectedNonce) {
		return reply.status(500).send({
			error: "Internal Error",
			message: "Challenge nonce is missing.",
		});
	}

	try {
		if (verificationType === "github-api") {
			// PATHWAY 1: GitHub API Micro-Verifier
			request.log.info(
				`ACME API-Verifier: Fetching challenge from GitHub for ${owner}/${repo}...`,
			);

			const fileUrl = `https://api.github.com/repos/${owner}/${repo}/contents/.well-known/sbom-challenge/token.txt`;
			// Use pass-through dev token if provided, or default GITHUB_TOKEN
			const devToken =
				request.headers["x-developer-token"] || process.env.GITHUB_TOKEN;
			const headers: Record<string, string> = {
				Accept: "application/vnd.github+json",
				"User-Agent": "Packablock-Registry",
			};
			if (devToken) {
				headers["Authorization"] = `Bearer ${devToken}`;
			}

			const res = await fetch(fileUrl, { headers });
			if (!res.ok) {
				return reply.status(400).send({
					error: "Verification Failed",
					message: `Failed to fetch challenge file from GitHub API. Ensure the file is placed at "/.well-known/sbom-challenge/token.txt" and is accessible.`,
				});
			}

			const fileData = (await res.json()) as any;
			const content = Buffer.from(fileData.content, "base64")
				.toString("utf8")
				.trim();

			if (content !== expectedNonce) {
				return reply.status(400).send({
					error: "Verification Failed",
					message: `Challenge mismatch. Expected "${expectedNonce}" but found "${content}".`,
				});
			}

			// Retrieve GPG signature from commit
			const commitsUrl = `https://api.github.com/repos/${owner}/${repo}/commits?path=.well-known/sbom-challenge/token.txt&per_page=1`;
			const commitRes = await fetch(commitsUrl, { headers });
			let publicKey = null;

			if (commitRes.ok) {
				const commitData = (await commitRes.json()) as any;
				if (commitData && commitData[0]) {
					const verification = commitData[0].commit.verification;
					if (verification && verification.verified) {
						publicKey = verification.signature || null;
					}
				}
			}

			// Promote status to verified!
			const activeToken = record.registration_token.replace(
				"pb_temp_",
				"pb_reg_",
			);

			// Update registration token and status in DB
			verifyAndActivateRepository(
				record.id,
				"verified",
				publicKey,
				activeToken,
			);

			return {
				success: true,
				owner: record.owner,
				repo: record.repo,
				verificationStatus: "verified",
				registrationToken: activeToken,
				message:
					"Repository verification successful. Public key has been pinned.",
			};
		} else if (verificationType === "github-attestation") {
			// PATHWAY 4: Zero-Access Cryptographic Provenance (Cosign/Sigstore Bundle)
			if (!attestationBundle) {
				return reply.status(400).send({
					error: "Bad Request",
					message:
						"attestationBundle parameter is required for github-attestation verificationType.",
				});
			}

			request.log.info(
				`ACME Attestation-Verifier: Verifying Sigstore attestation for ${owner}/${repo}...`,
			);

			// Write the bundle to a temporary file
			const path = await import("node:path");
			const tempPath = path.join(
				process.cwd(),
				`attestation_${record.id}.json`,
			);
			await Bun.write(tempPath, JSON.stringify(attestationBundle));

			try {
				// Execute the gh CLI command to verify GHA attestation
				const cmd = [
					"bash",
					"-c",
					`source .env.agy && export GH_TOKEN="$GITHUB_TOKEN" && export GITHUB_TOKEN="$GITHUB_TOKEN" && gh attestation verify "${tempPath}" --repo "${owner}/${repo}"`,
				];

				const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" });
				const exitCode = await proc.exited;

				if (exitCode !== 0) {
					const stderr = await new Response(proc.stderr).text();
					return reply.status(400).send({
						error: "Verification Failed",
						message: `Sigstore attestation validation failed: ${stderr.trim()}`,
					});
				}

				// Promote status to verified!
				const activeToken = record.registration_token.replace(
					"pb_temp_",
					"pb_reg_",
				);

				// Update status and token
				verifyAndActivateRepository(
					record.id,
					"verified",
					"sigstore_attested",
					activeToken,
				);

				return {
					success: true,
					owner: record.owner,
					repo: record.repo,
					verificationStatus: "verified",
					registrationToken: activeToken,
					message:
						"Repository verification successful via GitHub Artifact Attestation. Public key is pinned to Sigstore trust root.",
				};
			} finally {
				// Always clean up the temp file
				const fs = await import("node:fs");
				if (fs.existsSync(tempPath)) {
					fs.unlinkSync(tempPath);
				}
			}
		} else {
			return reply.status(400).send({
				error: "Bad Request",
				message:
					'Invalid verificationType. Supported values: "github-api", "github-attestation".',
			});
		}
	} catch (err: any) {
		request.log.error(err);
		return reply.status(500).send({
			error: "Internal Server Error",
			message: err.message,
		});
	}
});

/**
 * Helper to dispatch webhook payloads asynchronously with optional HMAC-SHA256 signature verification.
 */
async function dispatchWebhooks(
	repoId: number,
	owner: string,
	repo: string,
	event: string,
	details: any,
): Promise<void> {
	const hooks = getWebhooks(repoId);
	if (hooks.length === 0) return;

	const payload = {
		event,
		repository: `${owner}/${repo}`,
		timestamp: new Date().toISOString(),
		details,
	};

	const bodyStr = JSON.stringify(payload);

	for (const hook of hooks) {
		const headers: Record<string, string> = {
			"Content-Type": "application/json",
			"User-Agent": "Packablock-Registry-Webhooks",
		};

		if (hook.secret) {
			const crypto = await import("node:crypto");
			const signature = crypto
				.createHmac("sha256", hook.secret)
				.update(bodyStr)
				.digest("hex");
			headers["X-Packablock-Signature"] = signature;
		}

		// Asynchronous background fetch trigger (zero blocking to rest of request)
		fetch(hook.url, {
			method: "POST",
			headers,
			body: bodyStr,
			signal: AbortSignal.timeout(5000),
		}).catch((_err) => {
			console.error(`[Webhook Alert] Failed to dispatch to ${hook.url}`);
		});
	}
}

/**
 * Push cryptographically verified package chain to the database.
 * Supports metadata-free endpoints and dynamic Developer/CI authentication.
 */
server.post("/api/v1/log/push", async (request, reply) => {
	const chainContent = request.body as string;
	if (!chainContent || typeof chainContent !== "string") {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Package chain content must be sent as raw YAML body.",
		});
	}

	// Extract auth headers
	const authHeader = request.headers["authorization"];
	const repoTokenHeader = request.headers["x-repo-token"] as string | undefined;
	const oidcTokenHeader = request.headers["x-github-oidc-token"] as
		| string
		| undefined;
	const targetRepoHeader = request.headers["x-target-repo"] as
		| string
		| undefined; // Required for local OAuth developer pushes

	let resolvedRepo: { id: number; owner: string; repo: string } | null = null;
	let authType: "ci" | "developer" = "ci";

	// 1. Resolve Authorization Token (CI registration token vs Developer personal OAuth token)
	let token = "";
	if (repoTokenHeader) {
		token = repoTokenHeader;
	} else if (authHeader && authHeader.startsWith("Bearer ")) {
		token = authHeader.substring(7);
	}

	if (!token) {
		return reply.status(401).send({
			error: "Unauthorized",
			message:
				'Authentication required. Provide "X-Repo-Token" or "Authorization: Bearer <token>" header.',
		});
	}

	// Check if token exists in SQLite database as a registration token (CI Flow)
	const dbRepo = getRepositoryByToken(token);

	if (dbRepo) {
		resolvedRepo = dbRepo;
		authType = "ci";

		// Enforce GitHub OIDC Verification if the OIDC token is supplied in the headers
		if (oidcTokenHeader) {
			const repoPath = `${dbRepo.owner}/${dbRepo.repo}`;
			request.log.info(
				`Verifying GitHub Actions OIDC Token for repo: ${repoPath}`,
			);
			const oidcResult = await verifyGithubOidcToken(oidcTokenHeader, repoPath);

			if (!oidcResult.valid) {
				return reply.status(403).send({
					error: "Forbidden",
					message: `CI OIDC Token Verification Failed: ${oidcResult.reason}`,
				});
			}
			request.log.info(
				`OIDC Signature successfully validated for runner actor: ${oidcResult.payload?.actor}`,
			);
		}
	} else {
		// Treat as personal GitHub OAuth Token (Developer Flow)
		authType = "developer";

		if (!targetRepoHeader) {
			return reply.status(400).send({
				error: "Bad Request",
				message:
					'Personal OAuth push requires "X-Target-Repo: owner/repo" header to authorize collaboration write permissions.',
			});
		}

		const [owner, repo] = targetRepoHeader.split("/");
		if (!owner || !repo) {
			return reply.status(400).send({
				error: "Bad Request",
				message: 'Invalid "X-Target-Repo" format. Must be "owner/repo".',
			});
		}

		// Call GitHub API to identify the user
		request.log.info("Contacting GitHub API to identify local developer...");
		const userRes = await fetch("https://api.github.com/user", {
			headers: {
				Authorization: `Bearer ${token}`,
				Accept: "application/vnd.github+json",
				"User-Agent": "Packablock-Registry",
			},
		});

		if (!userRes.ok) {
			return reply.status(401).send({
				error: "Unauthorized",
				message: "GitHub OAuth token is invalid or expired.",
			});
		}

		const userData: any = await userRes.json();
		const username = userData.login;
		request.log.info(`Authenticated GitHub developer: ${username}`);

		// Call GitHub API to verify repository permissions
		request.log.info(
			`Checking write permissions for developer on ${targetRepoHeader}...`,
		);
		const repoRes = await fetch(
			`https://api.github.com/repos/${owner}/${repo}`,
			{
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/vnd.github+json",
					"User-Agent": "Packablock-Registry",
				},
			},
		);

		if (!repoRes.ok) {
			return reply.status(403).send({
				error: "Forbidden",
				message: `Failed to fetch repository metadata from GitHub. Verify repository path or access token: ${targetRepoHeader}`,
			});
		}

		const repoData: any = await repoRes.json();
		const permissions = repoData.permissions;

		const hasWriteAccess =
			permissions &&
			(permissions.push || permissions.admin || permissions.maintain);
		request.log.info(
			`Developer permissions on repo: push=${permissions?.push}, admin=${permissions?.admin}, maintain=${permissions?.maintain}`,
		);

		if (!hasWriteAccess) {
			return reply.status(403).send({
				error: "Forbidden",
				message: `Insufficient permissions. Developer requires "write", "push", "maintain", or "admin" permission on "${targetRepoHeader}".`,
			});
		}

		// User is authorized! Ensure repo exists in SQLite database, registering automatically if needed.
		let repoRecord = getRepositoryByPath(owner, repo);
		if (!repoRecord) {
			// Auto-register since collaborator possesses write permissions on GitHub
			request.log.info(
				`Repository "${targetRepoHeader}" not in database. Auto-registering...`,
			);
			const autoToken = "pb_reg_" + randomBytes(24).toString("hex");
			repoRecord = registerRepository(owner, repo, autoToken);
		}

		resolvedRepo = repoRecord;
	}

	if (!resolvedRepo) {
		return reply.status(401).send({
			error: "Unauthorized",
			message: "Token lookup or contributor authorization failed.",
		});
	}

	// 2. Cryptographically verify the in-memory chain
	request.log.info(
		`Verifying chain cryptographic hashes for repository ID: ${resolvedRepo.id}`,
	);
	const report = verifyInMemoryChain(chainContent);

	if (!report.valid) {
		// Dispatch failed push notification alerts to webhooks
		dispatchWebhooks(
			resolvedRepo.id,
			resolvedRepo.owner,
			resolvedRepo.repo,
			"push_failed_tampered",
			{
				reason: report.reason,
				blockIndex: report.blockIndex,
				tamperedComponent: report.tamperedComponent,
			},
		);

		return reply.status(422).send({
			error: "Unprocessable Entity",
			message: "Chain cryptographic verification failed.",
			details: {
				reason: report.reason,
				blockIndex: report.blockIndex,
				tamperedComponent: report.tamperedComponent,
				expected: report.expected,
				actual: report.actual,
			},
		});
	}

	// 3. Save the validated chain into SQLite
	try {
		const saved = saveLog(
			resolvedRepo.id,
			chainContent,
			report.blockCount!,
			report.lastBlockHash!,
		);
		request.log.info(
			`Successfully stored log for "${resolvedRepo.owner}/${resolvedRepo.repo}". Total blocks: ${report.blockCount}`,
		);

		// Dispatch push success alerts to webhooks
		dispatchWebhooks(
			resolvedRepo.id,
			resolvedRepo.owner,
			resolvedRepo.repo,
			"push_success",
			{
				blockCount: saved.block_count,
				lastBlockHash: saved.last_block_hash,
			},
		);

		return {
			success: true,
			message: "Package history pushed and validated successfully.",
			authType,
			repository: `${resolvedRepo.owner}/${resolvedRepo.repo}`,
			blockCount: saved.block_count,
			lastBlockHash: saved.last_block_hash,
			updatedAt: saved.updated_at,
		};
	} catch (err: any) {
		request.log.error(err);
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to save log history to database: ${err.message}`,
		});
	}
});

/**
 * Pull cryptographically verified package chain from the database.
 * Supports metadata-free requests (token or owner/repo header lookup).
 */
server.get("/api/v1/log/pull", async (request, reply) => {
	const tokenHeader = request.headers["x-repo-token"] as string | undefined;
	const authHeader = request.headers["authorization"];
	const targetRepoHeader = request.headers["x-target-repo"] as
		| string
		| undefined;

	let resolvedRepo: { id: number; owner: string; repo: string } | null = null;

	let token = "";
	if (tokenHeader) {
		token = tokenHeader;
	} else if (authHeader && authHeader.startsWith("Bearer ")) {
		token = authHeader.substring(7);
	}

	if (token) {
		// Try looking up via database token mapping (CI or saved credential)
		const dbRepo = getRepositoryByToken(token);
		if (dbRepo) {
			resolvedRepo = dbRepo;
		}
	}

	// Fallback to repository path lookup
	if (!resolvedRepo && targetRepoHeader) {
		const [owner, repo] = targetRepoHeader.split("/");
		if (owner && repo) {
			resolvedRepo = getRepositoryByPath(owner, repo);
		}
	}

	if (!resolvedRepo) {
		return reply.status(404).send({
			error: "Not Found",
			message: "Repository not found or access token unauthorized.",
		});
	}

	const logRecord = getLog(resolvedRepo.id);
	if (!logRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: `No log initialized for repository "${resolvedRepo.owner}/${resolvedRepo.repo}" yet.`,
		});
	}

	reply.header("Content-Type", "text/yaml");
	return logRecord.chain_content;
});

/**
 * Premium API: Retrieve latest upstream versions for packages.
 * Requires valid auth token (repo token or developer Bearer OAuth token).
 */
server.post("/api/v1/packages/latest", async (request, reply) => {
	const body = request.body as any;
	const packages = body?.packages as string[] | undefined;
	if (!packages || !Array.isArray(packages)) {
		return reply.status(400).send({
			error: "Bad Request",
			message: 'Body must contain a "packages" array of strings.',
		});
	}

	// Extract auth headers
	const authHeader = request.headers["authorization"];
	const repoTokenHeader = request.headers["x-repo-token"] as string | undefined;
	const targetRepoHeader = request.headers["x-target-repo"] as
		| string
		| undefined;

	let token = "";
	if (repoTokenHeader) {
		token = repoTokenHeader;
	} else if (authHeader && authHeader.startsWith("Bearer ")) {
		token = authHeader.substring(7);
	}

	if (!token) {
		return reply.status(401).send({
			error: "Unauthorized",
			message:
				"Authentication required. Upstream drift analysis is a premium feature.",
		});
	}

	// Validate the token using SQLite check (CI registration token check)
	const dbRepo = getRepositoryByToken(token);
	let isAuthorized = false;

	if (dbRepo) {
		isAuthorized = true;
	} else {
		// Check developer OAuth token
		if (!targetRepoHeader) {
			return reply.status(400).send({
				error: "Bad Request",
				message:
					'Personal OAuth requests require "X-Target-Repo: owner/repo" header.',
			});
		}

		const [owner, repo] = targetRepoHeader.split("/");
		if (!owner || !repo) {
			return reply.status(400).send({
				error: "Bad Request",
				message: 'Invalid "X-Target-Repo" format.',
			});
		}

		// Call GitHub API to identify the user
		try {
			const userRes = await fetch("https://api.github.com/user", {
				headers: {
					Authorization: `Bearer ${token}`,
					Accept: "application/vnd.github+json",
					"User-Agent": "Packablock-API",
				},
			});

			if (userRes.ok) {
				// Check write permission
				const repoRes = await fetch(
					`https://api.github.com/repos/${owner}/${repo}`,
					{
						headers: {
							Authorization: `Bearer ${token}`,
							Accept: "application/vnd.github+json",
							"User-Agent": "Packablock-Registry",
						},
					},
				);

				if (repoRes.ok) {
					const repoData: any = await repoRes.json();
					const permissions = repoData.permissions;
					if (
						permissions &&
						(permissions.push || permissions.admin || permissions.maintain)
					) {
						isAuthorized = true;
					}
				}
			}
		} catch (err) {
			// Ignore network errors, isAuthorized remains false
		}
	}

	if (!isAuthorized) {
		return reply.status(403).send({
			error: "Forbidden",
			message:
				"⭐ Premium Feature: Upstream drift analysis is only available to active paying customers of the hosted Packablock Registry.",
		});
	}

	// User is authorized! Fetch latest versions of the requested packages from NPM registry
	const results: Record<string, string> = {};

	await Promise.all(
		packages.map(async (pkg) => {
			try {
				const res = await fetch(`https://registry.npmjs.org/${pkg}/latest`, {
					signal: AbortSignal.timeout(3000),
				});
				if (res.ok) {
					const data = (await res.json()) as any;
					if (data && data.version) {
						results[pkg] = data.version;
					}
				}
			} catch (err) {
				// Fallback or ignore if fetch fails
			}
		}),
	);

	return {
		success: true,
		packages: results,
	};
});

/**
 * GET /api/v1/repo/:owner/:repo/history
 * Chronological sequence of block modifications, timestamps, and baselines.
 */
server.get("/api/v1/repo/:owner/:repo/history", async (request, reply) => {
	const { owner, repo } = request.params as any;
	if (!owner || !repo) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Fields 'owner' and 'repo' are required in route parameters.",
		});
	}

	const repoRecord = getRepositoryByPath(owner, repo);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "Repository not registered.",
		});
	}

	const logRecord = getLog(repoRecord.id);
	if (!logRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No package history log exists for this repository yet.",
		});
	}

	try {
		const docs = splitRawDocuments(logRecord.chain_content);
		const blockCount = docs.length / 2;
		const history = [];

		for (let i = 0; i < blockCount; i++) {
			const dataDocStr = docs[2 * i];
			const metaDocStr = docs[2 * i + 1];
			if (dataDocStr === undefined || metaDocStr === undefined) continue;

			const parsedData = YAML.parse(dataDocStr);
			const parsedMeta = YAML.parse(metaDocStr)?.["$yaml-chain-meta"];

			if (parsedMeta) {
				history.push({
					blockIndex: parsedMeta.block_index,
					timestamp: parsedMeta.timestamp,
					dataHash: parsedMeta.data_hash,
					metaHash: parsedMeta.meta_hash,
					prevMetaHash: parsedMeta.prev_meta_hash,
					packages: parsedData?.packages || {},
				});
			}
		}

		return {
			success: true,
			repository: `${repoRecord.owner}/${repoRecord.repo}`,
			blockCount,
			history,
		};
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to parse log history: ${err.message}`,
		});
	}
});

/**
 * GET /api/v1/repo/:owner/:repo/sigs
 * Historical signature auditing.
 */
server.get("/api/v1/repo/:owner/:repo/sigs", async (request, reply) => {
	const { owner, repo } = request.params as any;
	if (!owner || !repo) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Fields 'owner' and 'repo' are required in route parameters.",
		});
	}

	const repoRecord = getRepositoryByPath(owner, repo);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "Repository not registered.",
		});
	}

	const logRecord = getLog(repoRecord.id);
	if (!logRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No package history log exists for this repository yet.",
		});
	}

	try {
		const docs = splitRawDocuments(logRecord.chain_content);
		const blockCount = docs.length / 2;
		const signatures = [];

		for (let i = 0; i < blockCount; i++) {
			const metaDocStr = docs[2 * i + 1];
			if (metaDocStr === undefined) continue;

			const parsedMeta = YAML.parse(metaDocStr)?.["$yaml-chain-meta"];

			if (parsedMeta) {
				signatures.push({
					blockIndex: parsedMeta.block_index,
					timestamp: parsedMeta.timestamp,
					metaHash: parsedMeta.meta_hash,
					signingStrategy: parsedMeta.hashing_strategy || "raw",
					signature: parsedMeta.signature || null,
					committer: parsedMeta.committer || null,
					oidcClaims: parsedMeta.oidc_claims || null,
				});
			}
		}

		return {
			success: true,
			repository: `${repoRecord.owner}/${repoRecord.repo}`,
			blockCount,
			signatures,
		};
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to audit signatures: ${err.message}`,
		});
	}
});

/**
 * GET /api/v1/repo/:owner/:repo/tree
 * Returns a structured JSON visualization tree and flat graph representing the package chain blocks.
 */
server.get("/api/v1/repo/:owner/:repo/tree", async (request, reply) => {
	const { owner, repo } = request.params as any;
	if (!owner || !repo) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Fields 'owner' and 'repo' are required in route parameters.",
		});
	}

	const repoRecord = getRepositoryByPath(owner, repo);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "Repository not registered.",
		});
	}

	const logRecord = getLog(repoRecord.id);
	if (!logRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No package history log exists for this repository yet.",
		});
	}

	try {
		const docs = splitRawDocuments(logRecord.chain_content);
		const blockCount = docs.length / 2;

		interface TreeNode {
			id: string;
			name: string;
			blockIndex?: number;
			timestamp?: string;
			dataHash?: string;
			metaHash?: string;
			prevMetaHash?: string;
			committer?: string | null;
			type: "root" | "block" | "rollover";
			packagesCount?: number;
			children: TreeNode[];
		}

		interface GraphNode {
			id: string;
			label: string;
			blockIndex?: number;
			type: "root" | "block" | "rollover";
			packagesCount?: number;
		}

		interface GraphLink {
			source: string;
			target: string;
		}

		const nodesMap = new Map<string, TreeNode>();
		const flatNodes: GraphNode[] = [];
		const flatLinks: GraphLink[] = [];

		// Determine the base genesis hash
		let firstPrevHash =
			"0000000000000000000000000000000000000000000000000000000000000000";
		if (blockCount > 0) {
			const metaDocStr = docs[1];
			if (metaDocStr !== undefined) {
				const parsedMeta = YAML.parse(metaDocStr)?.["$yaml-chain-meta"];
				if (parsedMeta?.prev_meta_hash) {
					firstPrevHash = parsedMeta.prev_meta_hash;
				}
			}
		}

		// Create root node
		const rootNode: TreeNode = {
			id: firstPrevHash,
			name: "Genesis Anchor",
			type: "root",
			children: [],
		};
		nodesMap.set(firstPrevHash, rootNode);
		flatNodes.push({
			id: firstPrevHash,
			label: "Genesis Anchor",
			type: "root",
		});

		for (let i = 0; i < blockCount; i++) {
			const dataDocStr = docs[2 * i];
			const metaDocStr = docs[2 * i + 1];
			if (dataDocStr === undefined || metaDocStr === undefined) continue;

			const parsedData = YAML.parse(dataDocStr);
			const parsedMeta = YAML.parse(metaDocStr)?.["$yaml-chain-meta"];

			if (parsedMeta) {
				const metaHash = parsedMeta.meta_hash;
				const prevMetaHash = parsedMeta.prev_meta_hash || firstPrevHash;
				const packagesCount = parsedData?.packages
					? Object.keys(parsedData.packages).length
					: 0;
				const isRollover = !!parsedData?.genesis_rollover;

				const node: TreeNode = {
					id: metaHash,
					name: `Block #${parsedMeta.block_index}`,
					blockIndex: parsedMeta.block_index,
					timestamp: parsedMeta.timestamp,
					dataHash: parsedMeta.data_hash,
					metaHash: metaHash,
					prevMetaHash: prevMetaHash,
					committer: parsedMeta.committer || null,
					type: isRollover ? "rollover" : "block",
					packagesCount,
					children: [],
				};

				nodesMap.set(metaHash, node);
				flatNodes.push({
					id: metaHash,
					label: `Block #${parsedMeta.block_index}`,
					blockIndex: parsedMeta.block_index,
					type: isRollover ? "rollover" : "block",
					packagesCount,
				});

				flatLinks.push({
					source: prevMetaHash,
					target: metaHash,
				});
			}
		}

		// Build hierarchy
		for (const [_, node] of nodesMap) {
			if (node.type === "root") continue;
			const parentHash = node.prevMetaHash;
			if (parentHash && nodesMap.has(parentHash)) {
				nodesMap.get(parentHash)!.children.push(node);
			} else {
				// If parent not in map (should not happen in a valid chain), attach to root
				rootNode.children.push(node);
			}
		}

		return {
			success: true,
			repository: `${repoRecord.owner}/${repoRecord.repo}`,
			blockCount,
			tree: rootNode,
			graph: {
				nodes: flatNodes,
				links: flatLinks,
			},
		};
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to generate visualization tree: ${err.message}`,
		});
	}
});

/**
 * POST /api/v1/repo/:owner/:repo/webhooks
 * Registers a new webhook URL.
 */
server.post("/api/v1/repo/:owner/:repo/webhooks", async (request, reply) => {
	const { owner, repo } = request.params as any;
	const body = request.body as any;
	const url = body?.url as string | undefined;
	const secret = body?.secret as string | undefined;

	if (!owner || !repo || !url) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Fields 'owner', 'repo', and body parameter 'url' are required.",
		});
	}

	const repoRecord = getRepositoryByPath(owner, repo);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "Repository not registered.",
		});
	}

	try {
		const webhook = addWebhook(repoRecord.id, url, secret || null);
		return {
			success: true,
			message: "Webhook registered successfully.",
			webhook,
		};
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: err.message,
		});
	}
});

/**
 * GET /api/v1/repo/:owner/:repo/webhooks
 * Lists all registered webhooks for a repository.
 */
server.get("/api/v1/repo/:owner/:repo/webhooks", async (request, reply) => {
	const { owner, repo } = request.params as any;
	if (!owner || !repo) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Fields 'owner' and 'repo' are required.",
		});
	}

	const repoRecord = getRepositoryByPath(owner, repo);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: "Repository not registered.",
		});
	}

	try {
		const webhooks = getWebhooks(repoRecord.id);
		return {
			success: true,
			webhooks,
		};
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: err.message,
		});
	}
});

/**
 * DELETE /api/v1/repo/:owner/:repo/webhooks/:id
 * Deletes a registered webhook.
 */
server.delete(
	"/api/v1/repo/:owner/:repo/webhooks/:id",
	async (request, reply) => {
		const { owner, repo, id } = request.params as any;
		if (!owner || !repo || !id) {
			return reply.status(400).send({
				error: "Bad Request",
				message: "Fields 'owner', 'repo', and 'id' are required.",
			});
		}

		const repoRecord = getRepositoryByPath(owner, repo);
		if (!repoRecord) {
			return reply.status(404).send({
				error: "Not Found",
				message: "Repository not registered.",
			});
		}

		try {
			const deleted = deleteWebhook(parseInt(id, 10), repoRecord.id);
			if (!deleted) {
				return reply.status(404).send({
					error: "Not Found",
					message: "Webhook entry not found or unauthorized.",
				});
			}

			return {
				success: true,
				message: "Webhook deleted successfully.",
			};
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

/**
 * Starts the server on the specified port.
 */
export async function startServer(port = 3000): Promise<void> {
	// Initialize database schema
	initDb();

	try {
		await server.listen({ port, host: "0.0.0.0" });
		console.log(
			`🚀 Packablock Supply Chain Trust Registry successfully listening on http://localhost:${port}`,
		);
	} catch (err) {
		server.log.error(err);
		process.exit(1);
	}
}
