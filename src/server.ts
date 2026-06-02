import fastify from "fastify";
import { randomBytes } from "node:crypto";
import YAML from "yaml";
import {
	initDb,
	registerRepository,
	getRepositoryByToken,
	getRepositoryByPath,
	getRepositoryById,
	saveLog,
	getLog,
	registerPremiumPending,
	verifyAndActivateRepository,
	addWebhook,
	getWebhooks,
	deleteWebhook,
	archiveLog,
	getArchivedLogs,
	getCachedPackage,
	saveCachedPackage,
	logIntegrationEvent,
	getIntegrationEvents,
	createProject,
	linkRepoToProject,
	getProjects,
	getProjectDetails,
	getProjectRepos,
	getAllRepos,
	togglePremium,
	revokeRepositoryToken,
} from "./database.js";
import { verifyInMemoryChain, splitRawDocuments } from "./verify.js";
import { verifyGithubOidcToken } from "./oidc.js";
import { adminHtml } from "./adminHtml.js";

/**
 * Resolves the signing identity badge based on available metadata.
 */
export function resolveIdentityBadge(parsedMeta: any): string | null {
	if (!parsedMeta) return null;
	if (parsedMeta.oidc_claims?.actor) {
		return `OIDC: ${parsedMeta.oidc_claims.actor}`;
	}
	const sshFingerprint =
		parsedMeta.ssh_fingerprint || parsedMeta.ssh_key_fingerprint;
	if (sshFingerprint) {
		return `SSH: ${sshFingerprint}`;
	}
	const gitActor = parsedMeta.git_actor || parsedMeta.committer;
	if (gitActor) {
		return `Git: ${gitActor}`;
	}
	if (parsedMeta.gpg_signature) {
		return "GPG Signed";
	}
	return null;
}

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
 * Root route - redirects to administrative dashboard
 */
server.get("/", async (request, reply) => {
	return reply.redirect("/admin");
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

			let content = "";
			let publicKey: string | null = null;

			if (process.env.MOCK_GITHUB_API === "true") {
				content = expectedNonce;
				publicKey = "mock_gpg_signature";
			} else {
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
				content = Buffer.from(fileData.content, "base64")
					.toString("utf8")
					.trim();

				// Retrieve GPG signature from commit
				const commitsUrl = `https://api.github.com/repos/${owner}/${repo}/commits?path=.well-known/sbom-challenge/token.txt&per_page=1`;
				const commitRes = await fetch(commitsUrl, { headers });

				if (commitRes.ok) {
					const commitData = (await commitRes.json()) as any;
					if (commitData && commitData[0]) {
						const verification = commitData[0].commit.verification;
						if (verification && verification.verified) {
							publicKey = verification.signature || null;
						}
					}
				}
			}

			if (content !== expectedNonce) {
				return reply.status(400).send({
					error: "Verification Failed",
					message: `Challenge mismatch. Expected "${expectedNonce}" but found "${content}".`,
				});
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
				let exitCode = 0;
				let stderr = "";

				if (process.env.MOCK_GITHUB_API === "true") {
					exitCode = 0;
				} else {
					// Execute the gh CLI command to verify GHA attestation
					const cmd = [
						"bash",
						"-c",
						`source .env.agy && export GH_TOKEN="$GITHUB_TOKEN" && export GITHUB_TOKEN="$GITHUB_TOKEN" && gh attestation verify "${tempPath}" --repo "${owner}/${repo}"`,
					];

					const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe" });
					exitCode = await proc.exited;

					if (exitCode !== 0) {
						stderr = await new Response(proc.stderr).text();
					}
				}

				if (exitCode !== 0) {
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

interface SemVerWarning {
	package: string;
	type: string;
	reason: string;
	severity: "warning" | "critical";
}

function parsePackages(dataObj: any): Record<string, string> {
	const pkgs: Record<string, string> = {};
	if (!dataObj || !dataObj.packages || typeof dataObj.packages !== "object") {
		return pkgs;
	}
	for (const [name, val] of Object.entries(dataObj.packages)) {
		if (typeof val === "string") {
			pkgs[name] = val;
		} else if (val && typeof val === "object" && (val as any).version) {
			pkgs[name] = (val as any).version;
		}
	}
	return pkgs;
}

function auditSemVerHealth(
	oldPkgs: Record<string, string>,
	newPkgs: Record<string, string>,
): SemVerWarning[] {
	const warnings: SemVerWarning[] = [];

	for (const [name, newVer] of Object.entries(newPkgs)) {
		// 1. Check Open Fuse Constraint
		if (
			newVer.includes(">=") ||
			newVer.includes(">") ||
			newVer.includes("*") ||
			newVer.toLowerCase().includes("x")
		) {
			warnings.push({
				package: name,
				type: "open_fuse_rule",
				reason: `Open-ended constraint detected in package '${name}': '${newVer}'`,
				severity: "critical",
			});
			continue;
		}

		const oldVer = oldPkgs[name];
		if (oldVer) {
			const parseVersion = (v: string) => {
				const parts = v
					.replace(/[^0-9.]/g, "")
					.split(".")
					.map(Number);
				return {
					major: parts[0] ?? 0,
					minor: parts[1] ?? 0,
					patch: parts[2] ?? 0,
				};
			};

			const oldSem = parseVersion(oldVer);
			const newSem = parseVersion(newVer);

			// 2. Downgrade/Regression Warning
			if (
				newSem.major < oldSem.major ||
				(newSem.major === oldSem.major && newSem.minor < oldSem.minor) ||
				(newSem.major === oldSem.major &&
					newSem.minor === oldSem.minor &&
					newSem.patch < oldSem.patch)
			) {
				warnings.push({
					package: name,
					type: "dependency_regression",
					reason: `Version regression detected for package '${name}' from '${oldVer}' to '${newVer}'`,
					severity: "critical",
				});
			}
			// 3. Technical Debt Wall (Major Version Jump)
			else if (newSem.major > oldSem.major) {
				warnings.push({
					package: name,
					type: "technical_debt_wall",
					reason: `Major version upgrade detected for package '${name}' from '${oldVer}' to '${newVer}' (Technical Debt Wall)`,
					severity: "warning",
				});
			}
			// 4. High Velocity Drift Check (Minor version jump > 2 versions)
			else if (newSem.minor > oldSem.minor + 2) {
				warnings.push({
					package: name,
					type: "high_drift_velocity",
					reason: `High drift velocity detected for package '${name}' upgrading from '${oldVer}' to '${newVer}'`,
					severity: "warning",
				});
			}
		}
	}

	return warnings;
}

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

		// Extract client execution metadata headers
		const clientVersion = request.headers["x-client-version"] as
			| string
			| undefined;
		const osPlatform = request.headers["x-client-os"] as string | undefined;
		const runtimeEnv = request.headers["x-client-env"] as string | undefined;
		const isCiHeader = request.headers["x-client-ci"] as string | undefined;
		const gitActorHeader = request.headers["x-client-actor"] as
			| string
			| undefined;
		const clientIp =
			request.ip || request.headers["x-forwarded-for"] || "127.0.0.1";

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

		// Issue #9: SemVer Webhooks Pipeline triggers
		dispatchWebhooks(
			resolvedRepo.id,
			resolvedRepo.owner,
			resolvedRepo.repo,
			"chain.pushed",
			{
				blockIndex: report.blockIndex,
				version: report.version,
				metaHash: report.lastBlockHash,
				timestamp: new Date().toISOString(),
				actor: gitActorHeader || "unknown",
			},
		);

		const docs = splitRawDocuments(chainContent);
		const blockCount = docs.length / 2;
		let newPkgData: any = {};
		let oldPkgData: any = {};

		if (blockCount >= 1) {
			try {
				const lastDataStr = docs[2 * (blockCount - 1)];
				if (lastDataStr) {
					newPkgData = YAML.parse(lastDataStr);
				}
			} catch (e) {}

			if (blockCount >= 2) {
				try {
					const prevDataStr = docs[2 * (blockCount - 2)];
					if (prevDataStr) {
						oldPkgData = YAML.parse(prevDataStr);
					}
				} catch (e) {}
			} else {
				try {
					const archived = getArchivedLogs(resolvedRepo.id);
					if (archived.length > 0) {
						const lastArchived = archived[archived.length - 1];
						if (lastArchived) {
							const archDocs = splitRawDocuments(lastArchived.chain_content);
							const archBlockCount = archDocs.length / 2;
							if (archBlockCount >= 1) {
								const lastArchDataStr = archDocs[2 * (archBlockCount - 1)];
								if (lastArchDataStr) {
									oldPkgData = YAML.parse(lastArchDataStr);
								}
							}
						}
					}
				} catch (e) {}
			}
		}

		const oldPkgs = parsePackages(oldPkgData);
		const newPkgs = parsePackages(newPkgData);

		// Compute added and updated diffs
		for (const [name, newVer] of Object.entries(newPkgs)) {
			const oldVer = oldPkgs[name];
			if (oldVer === undefined) {
				dispatchWebhooks(
					resolvedRepo.id,
					resolvedRepo.owner,
					resolvedRepo.repo,
					"package.added",
					{
						package: name,
						version: newVer,
					},
				);
			} else if (oldVer !== newVer) {
				dispatchWebhooks(
					resolvedRepo.id,
					resolvedRepo.owner,
					resolvedRepo.repo,
					"package.updated",
					{
						package: name,
						oldVersion: oldVer,
						newVersion: newVer,
					},
				);
			}
		}

		// SemVer health warnings
		const healthWarnings = auditSemVerHealth(oldPkgs, newPkgs);
		for (const warning of healthWarnings) {
			dispatchWebhooks(
				resolvedRepo.id,
				resolvedRepo.owner,
				resolvedRepo.repo,
				"health.warning",
				{
					package: warning.package,
					warningType: warning.type,
					reason: warning.reason,
					severity: warning.severity,
				},
			);
		}

		logIntegrationEvent(resolvedRepo.id, {
			client_version: clientVersion || null,
			os_platform: osPlatform || null,
			runtime_env: runtimeEnv || null,
			is_ci: isCiHeader === "true" ? 1 : 0,
			client_ip:
				(Array.isArray(clientIp) ? clientIp[0] : (clientIp as string)) ||
				"127.0.0.1",
			git_actor: gitActorHeader || null,
		});

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
 * Coordinate key rollover and archive the legacy package chain history.
 * POST /api/v1/repo/:owner/:repo/rollover
 */
server.post("/api/v1/repo/:owner/:repo/rollover", async (request, reply) => {
	const { owner, repo } = request.params as { owner: string; repo: string };
	const body = request.body as any;

	if (!body || !body.previous_chain_hash || !body.new_genesis_block) {
		return reply.status(400).send({
			error: "Bad Request",
			message:
				'Fields "previous_chain_hash" and "new_genesis_block" are required in body.',
		});
	}

	const { previous_chain_hash, new_genesis_block } = body;

	// Extract auth headers
	const authHeader = request.headers["authorization"];
	const repoTokenHeader = request.headers["x-repo-token"] as string | undefined;

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

	// Resolve repo by token
	const tokenRepo = getRepositoryByToken(token);
	if (
		!tokenRepo ||
		tokenRepo.owner.toLowerCase() !== owner.toLowerCase() ||
		tokenRepo.repo.toLowerCase() !== repo.toLowerCase()
	) {
		return reply.status(403).send({
			error: "Forbidden",
			message: "Invalid registration token for this repository path.",
		});
	}

	// Fetch current active log
	const activeLog = getLog(tokenRepo.id);
	if (!activeLog) {
		return reply.status(400).send({
			error: "Bad Request",
			message:
				"No active package log found to roll over. Push an initial chain log first.",
		});
	}

	// Assert previous_chain_hash matches activeLog.last_block_hash
	if (activeLog.last_block_hash !== previous_chain_hash) {
		return reply.status(409).send({
			error: "Conflict",
			message: `Rollover alignment mismatch. Current anchored hash is '${activeLog.last_block_hash}', but client provided '${previous_chain_hash}'.`,
		});
	}

	// Verify the new genesis block
	const report = verifyInMemoryChain(new_genesis_block);
	if (!report.valid) {
		return reply.status(422).send({
			error: "Unprocessable Entity",
			message: `Invalid new genesis block chain content: ${report.reason}`,
		});
	}

	// Check that the new genesis block links back correctly
	const docs = splitRawDocuments(new_genesis_block);
	if (docs.length < 2) {
		return reply.status(400).send({
			error: "Bad Request",
			message:
				"New genesis block must contain exactly one data doc and one meta doc.",
		});
	}
	const metaDoc = YAML.parse(docs[1]!);
	const meta = metaDoc?.["$yaml-chain-meta"];
	if (!meta || meta.block_index !== 0) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Invalid rollover block index: must be genesis (index 0).",
		});
	}
	if (meta.prev_meta_hash !== previous_chain_hash) {
		return reply.status(400).send({
			error: "Bad Request",
			message: `New genesis block prev_meta_hash '${meta.prev_meta_hash}' does not match expected '${previous_chain_hash}'.`,
		});
	}

	try {
		// 1. Archive the old active log
		archiveLog(
			tokenRepo.id,
			activeLog.chain_content,
			activeLog.block_count,
			activeLog.last_block_hash,
		);

		// 2. Save the new genesis block as the new active log
		saveLog(tokenRepo.id, new_genesis_block, 1, report.lastBlockHash!);

		return {
			success: true,
			owner,
			repo,
			archivedBlockCount: activeLog.block_count,
			archivedChainHash: activeLog.last_block_hash,
			newGenesisHash: report.lastBlockHash,
			message:
				"Key rotation boundary coordinated and legacy log archived successfully.",
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
 * Retrieve all archived logs for a repository.
 * GET /api/v1/repo/:owner/:repo/archive
 */
server.get("/api/v1/repo/:owner/:repo/archive", async (request, reply) => {
	const { owner, repo } = request.params as { owner: string; repo: string };

	// Resolve repository
	const record = getRepositoryByPath(owner, repo);
	if (!record) {
		return reply.status(404).send({
			error: "Not Found",
			message: `Repository not found: "${owner}/${repo}".`,
		});
	}

	try {
		const archives = getArchivedLogs(record.id);
		return {
			success: true,
			owner,
			repo,
			archives: archives.map((archive) => ({
				epochIndex: archive.epoch_index,
				blockCount: archive.block_count,
				lastBlockHash: archive.last_block_hash,
				chainContent: archive.chain_content,
				archivedAt: archive.archived_at,
			})),
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
					"User-Agent": "Packablock-Registry",
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

	// User is authorized! Fetch latest versions of the requested packages with caching
	const results: Record<string, string> = {};
	const cacheTtlMs = process.env.PACKAGE_CACHE_TTL_MS
		? Number.parseInt(process.env.PACKAGE_CACHE_TTL_MS, 10)
		: 3600000; // Default: 1 hour

	await Promise.all(
		packages.map(async (pkg) => {
			// 1. Try reading from persistent SQLite cache first
			try {
				const cachedVersion = getCachedPackage(pkg, cacheTtlMs);
				if (cachedVersion !== null) {
					results[pkg] = cachedVersion;
					return;
				}
			} catch (err) {
				// Fallback to fetching
			}

			// 2. Fetch from upstream NPM registry
			try {
				const res = await fetch(`https://registry.npmjs.org/${pkg}/latest`, {
					signal: AbortSignal.timeout(3000),
				});
				if (res.ok) {
					const data = (await res.json()) as any;
					if (data && data.version) {
						results[pkg] = data.version;
						// Save to cache
						try {
							saveCachedPackage(pkg, data.version);
						} catch (e) {}
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
 * GET /api/v1/repo/:id/history
 * Retrieve chronological package chain blocks for a repository by its database ID.
 */
server.get("/api/v1/repo/:id/history", async (request, reply) => {
	const { id } = request.params as { id: string };
	const repoId = Number.parseInt(id, 10);
	if (Number.isNaN(repoId)) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Invalid repository ID format.",
		});
	}

	const repoRecord = getRepositoryById(repoId);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: `Repository with ID ${repoId} not registered.`,
		});
	}

	const logRecord = getLog(repoRecord.id);
	const archivedLogs = getArchivedLogs(repoRecord.id);

	if (!logRecord && archivedLogs.length === 0) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No package history log exists for this repository yet.",
		});
	}

	try {
		const history: any[] = [];
		const logsToProcess: Array<{ chain_content: string }> = [...archivedLogs];
		if (logRecord) {
			logsToProcess.push(logRecord);
		}

		for (const log of logsToProcess) {
			const docs = splitRawDocuments(log.chain_content);
			const blockCount = docs.length / 2;
			for (let i = 0; i < blockCount; i++) {
				const dataDocStr = docs[2 * i];
				const metaDocStr = docs[2 * i + 1];
				if (dataDocStr === undefined || metaDocStr === undefined) continue;

				const parsedData = YAML.parse(dataDocStr);
				const parsedMeta = YAML.parse(metaDocStr)?.["$yaml-chain-meta"];

				if (parsedMeta) {
					history.push({
						...parsedData,
						version: parsedMeta.version,
						block_index: parsedMeta.block_index,
						timestamp: parsedMeta.timestamp,
						data_hash: parsedMeta.data_hash,
						prev_meta_hash: parsedMeta.prev_meta_hash,
						meta_hash: parsedMeta.meta_hash,
					});
				}
			}
		}

		return history;
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to parse log history: ${err.message}`,
		});
	}
});

/**
 * GET /api/v1/repo/:id/sigs
 * Historical signature auditing for a repository by its database ID.
 */
server.get("/api/v1/repo/:id/sigs", async (request, reply) => {
	const { id } = request.params as { id: string };
	const repoId = Number.parseInt(id, 10);
	if (Number.isNaN(repoId)) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Invalid repository ID format.",
		});
	}

	const repoRecord = getRepositoryById(repoId);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: `Repository with ID ${repoId} not registered.`,
		});
	}

	const logRecord = getLog(repoRecord.id);
	const archivedLogs = getArchivedLogs(repoRecord.id);

	if (!logRecord && archivedLogs.length === 0) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No package history log exists for this repository yet.",
		});
	}

	try {
		const signatures: any[] = [];
		const logsToProcess: Array<{ chain_content: string }> = [...archivedLogs];
		if (logRecord) {
			logsToProcess.push(logRecord);
		}

		for (const log of logsToProcess) {
			const docs = splitRawDocuments(log.chain_content);
			const blockCount = docs.length / 2;
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
						sshFingerprint:
							parsedMeta.ssh_fingerprint ||
							parsedMeta.ssh_key_fingerprint ||
							null,
						gpgSignature: parsedMeta.gpg_signature || null,
						gitActor: parsedMeta.git_actor || parsedMeta.committer || null,
					});
				}
			}
		}

		return signatures;
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to audit signatures: ${err.message}`,
		});
	}
});

/**
 * GET /api/v1/repo/:id/tree
 * Returns a structured JSON visualization tree and flat graph representing the complete package chain blocks.
 */
server.get("/api/v1/repo/:id/tree", async (request, reply) => {
	const { id } = request.params as { id: string };
	const repoId = Number.parseInt(id, 10);
	if (Number.isNaN(repoId)) {
		return reply.status(400).send({
			error: "Bad Request",
			message: "Invalid repository ID format.",
		});
	}

	const repoRecord = getRepositoryById(repoId);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: `Repository with ID ${repoId} not registered.`,
		});
	}

	const logRecord = getLog(repoRecord.id);
	const archivedLogs = getArchivedLogs(repoRecord.id);

	if (!logRecord && archivedLogs.length === 0) {
		return reply.status(404).send({
			error: "Not Found",
			message: "No package history log exists for this repository yet.",
		});
	}

	try {
		const blocks: Array<{
			dataDocStr: string;
			metaDocStr: string;
		}> = [];

		for (const log of archivedLogs) {
			const docs = splitRawDocuments(log.chain_content);
			const blockCount = docs.length / 2;
			for (let i = 0; i < blockCount; i++) {
				const dataDocStr = docs[2 * i];
				const metaDocStr = docs[2 * i + 1];
				if (dataDocStr !== undefined && metaDocStr !== undefined) {
					blocks.push({ dataDocStr, metaDocStr });
				}
			}
		}

		if (logRecord) {
			const docs = splitRawDocuments(logRecord.chain_content);
			const blockCount = docs.length / 2;
			for (let i = 0; i < blockCount; i++) {
				const dataDocStr = docs[2 * i];
				const metaDocStr = docs[2 * i + 1];
				if (dataDocStr !== undefined && metaDocStr !== undefined) {
					blocks.push({ dataDocStr, metaDocStr });
				}
			}
		}

		interface TreeNode {
			id: string;
			name: string;
			block_index?: number;
			version?: string;
			timestamp?: string;
			data_hash?: string;
			prev_meta_hash?: string;
			meta_hash?: string;
			identityBadge?: string | null;
			type: "root" | "block" | "rollover";
			children: TreeNode[];
		}

		interface GraphNode {
			id: string;
			label: string;
			block_index?: number;
			version?: string;
			timestamp?: string;
			data_hash?: string;
			prev_meta_hash?: string;
			meta_hash?: string;
			identityBadge?: string | null;
			type: "root" | "block" | "rollover";
		}

		interface GraphEdge {
			source: string;
			target: string;
		}

		const nodesMap = new Map<string, TreeNode>();
		const flatNodes: GraphNode[] = [];
		const flatEdges: GraphEdge[] = [];

		let firstPrevHash =
			"0000000000000000000000000000000000000000000000000000000000000000";
		const firstBlock = blocks[0];
		if (firstBlock) {
			try {
				const parsedMeta = YAML.parse(firstBlock.metaDocStr)?.[
					"$yaml-chain-meta"
				];
				if (parsedMeta?.prev_meta_hash) {
					firstPrevHash = parsedMeta.prev_meta_hash;
				}
			} catch (e) {}
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

		for (const block of blocks) {
			try {
				const parsedData = YAML.parse(block.dataDocStr);
				const parsedMeta = YAML.parse(block.metaDocStr)?.["$yaml-chain-meta"];

				if (parsedMeta) {
					const metaHash = parsedMeta.meta_hash;
					const prevMetaHash = parsedMeta.prev_meta_hash || firstPrevHash;
					const isRollover = !!parsedData?.genesis_rollover;
					const badge = resolveIdentityBadge(parsedMeta);

					const node: TreeNode = {
						id: metaHash,
						name: `Block #${parsedMeta.block_index}`,
						block_index: parsedMeta.block_index,
						version: parsedMeta.version,
						timestamp: parsedMeta.timestamp,
						data_hash: parsedMeta.data_hash,
						prev_meta_hash: prevMetaHash,
						meta_hash: metaHash,
						identityBadge: badge,
						type: isRollover ? "rollover" : "block",
						children: [],
					};

					nodesMap.set(metaHash, node);

					flatNodes.push({
						id: metaHash,
						label: `Block #${parsedMeta.block_index}`,
						block_index: parsedMeta.block_index,
						version: parsedMeta.version,
						timestamp: parsedMeta.timestamp,
						data_hash: parsedMeta.data_hash,
						prev_meta_hash: prevMetaHash,
						meta_hash: metaHash,
						identityBadge: badge,
						type: isRollover ? "rollover" : "block",
					});

					flatEdges.push({
						source: prevMetaHash,
						target: metaHash,
					});
				}
			} catch (e) {
				// Ignore malformed block parsing
			}
		}

		// Build hierarchy
		for (const [_, node] of nodesMap) {
			if (node.type === "root") continue;
			const parentHash = node.prev_meta_hash;
			if (parentHash && nodesMap.has(parentHash)) {
				nodesMap.get(parentHash)!.children.push(node);
			} else {
				// Fallback to attaching to root
				rootNode.children.push(node);
			}
		}

		return {
			success: true,
			repository: `${repoRecord.owner}/${repoRecord.repo}`,
			blockCount: blocks.length,
			tree: rootNode,
			graph: {
				nodes: flatNodes,
				edges: flatEdges,
			},
		};
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: `Failed to construct visualization tree: ${err.message}`,
		});
	}
});

/**
 * POST /api/v1/alerts
 * Register a new outbound webhook alert.
 */
server.post("/api/v1/alerts", async (request, reply) => {
	const body = request.body as {
		repo_id?: number | string;
		url?: string;
		secret?: string;
	};

	if (!body || body.repo_id === undefined || !body.url) {
		return reply.status(400).send({
			error: "Bad Request",
			message: 'Fields "repo_id" and "url" are required in request body.',
		});
	}

	const repoId =
		typeof body.repo_id === "string"
			? Number.parseInt(body.repo_id, 10)
			: body.repo_id;
	if (typeof repoId !== "number" || Number.isNaN(repoId)) {
		return reply.status(400).send({
			error: "Bad Request",
			message: 'Field "repo_id" must be a valid integer.',
		});
	}

	const repoRecord = getRepositoryById(repoId);
	if (!repoRecord) {
		return reply.status(404).send({
			error: "Not Found",
			message: `Repository with ID ${repoId} not registered.`,
		});
	}

	try {
		const secret = body.secret || null;
		const webhook = addWebhook(repoId, body.url, secret);
		return reply.status(201).send(webhook);
	} catch (err: any) {
		return reply.status(500).send({
			error: "Internal Server Error",
			message: err.message,
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
 * ==========================================================================
 * ADMINISTRATIVE DASHBOARD WEB UI & PROJECTS API ROUTES (Milestone api #10)
 * ==========================================================================
 */

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "admin_secret_token_1234";

async function verifyAdminAuth(request: any, reply: any) {
	const authHeader = request.headers["authorization"];
	let token = "";
	if (authHeader && authHeader.startsWith("Bearer ")) {
		token = authHeader.substring(7);
	} else {
		const cookieHeader = request.headers["cookie"];
		if (cookieHeader) {
			const cookies = cookieHeader.split(";").reduce((acc: any, c: string) => {
				const [k, v] = c.trim().split("=");
				if (k && v) acc[k] = decodeURIComponent(v);
				return acc;
			}, {});
			token = cookies["pb_admin_session"] || "";
		}
	}

	if (token !== ADMIN_TOKEN) {
		return reply.status(401).send({
			error: "Unauthorized",
			message: "Invalid or missing administrator session credentials.",
		});
	}
}

// 1. GET /admin: Serves the high-fidelity admin dashboard sitemap SPA
server.get("/admin", async (request, reply) => {
	reply.type("text/html").send(adminHtml);
});

// 2. POST /api/v1/admin/login: Sets the HTTP-only admin session cookie
server.post("/api/v1/admin/login", async (request, reply) => {
	const body = request.body as any;
	const token = body?.token;

	if (token === ADMIN_TOKEN) {
		return { success: true };
	} else {
		return reply.status(401).send({
			error: "Unauthorized",
			message: "Incorrect administrator access token.",
		});
	}
});

// 3. GET /api/v1/admin/projects: List all projects mapped in registry
server.get(
	"/api/v1/admin/projects",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		try {
			const projects = getProjects();
			return { success: true, projects };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 4. POST /api/v1/admin/projects: Create a new project container
server.post(
	"/api/v1/admin/projects",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		const body = request.body as any;
		const name = body?.name;

		if (!name || typeof name !== "string") {
			return reply.status(400).send({
				error: "Bad Request",
				message: "Project name is required.",
			});
		}

		try {
			const project = createProject(name);
			return { success: true, project };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 5. POST /api/v1/admin/projects/link: Groups a repo under a project
server.post(
	"/api/v1/admin/projects/link",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		const body = request.body as any;
		const repoId = body?.repoId;
		const projectId = body?.projectId;

		if (repoId === undefined) {
			return reply.status(400).send({
				error: "Bad Request",
				message: "repoId parameter is required.",
			});
		}

		try {
			linkRepoToProject(repoId, projectId || null);
			return { success: true };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 6. GET /api/v1/admin/repos: Lists all registered repositories
server.get(
	"/api/v1/admin/repos",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		try {
			const repos = getAllRepos();
			return { success: true, repos };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 7. GET /api/v1/admin/projects/:id/checks: Detailed state and timeline logs of repos mapped to project
server.get(
	"/api/v1/admin/projects/:id/checks",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		const { id } = request.params as any;
		try {
			const repos = getProjectRepos(id);
			const enrichedRepos = repos.map((r) => {
				const log = getLog(r.id);
				return {
					...r,
					log: log || null,
				};
			});
			return { success: true, repos: enrichedRepos };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 8. GET /api/v1/admin/projects/:id/integrations: Client pushes and runner metadata auditing events
server.get(
	"/api/v1/admin/projects/:id/integrations",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		const { id } = request.params as any;
		try {
			const repos = getProjectRepos(id);
			let allEvents: any[] = [];
			for (const r of repos) {
				const events = getIntegrationEvents(r.id);
				const mappedEvents = events.map((e) => ({
					...e,
					owner: r.owner,
					repo: r.repo,
				}));
				allEvents = [...allEvents, ...mappedEvents];
			}
			// Sort events chronologically descending
			allEvents.sort(
				(a, b) =>
					new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
			);
			return { success: true, events: allEvents };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 9. POST /api/v1/admin/repo/:id/toggle-premium: Toggles premium access and promotions
server.post(
	"/api/v1/admin/repo/:id/toggle-premium",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		const { id } = request.params as any;
		try {
			togglePremium(parseInt(id, 10));
			return { success: true };
		} catch (err: any) {
			return reply.status(500).send({
				error: "Internal Server Error",
				message: err.message,
			});
		}
	},
);

// 10. POST /api/v1/admin/repo/:id/revoke: Revokes access token
server.post(
	"/api/v1/admin/repo/:id/revoke",
	{ preHandler: verifyAdminAuth },
	async (request, reply) => {
		const { id } = request.params as any;
		try {
			revokeRepositoryToken(parseInt(id, 10));
			return { success: true };
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
