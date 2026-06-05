import { Database } from "bun:sqlite";
import path from "node:path";
import { watch } from "node:fs";

let db: Database;
let DB_FILE = "";
let watcher: any = null;

export interface RepositoryRecord {
	id: number;
	owner: string;
	repo: string;
	registration_token: string;
	created_at: string;
	is_premium: number;
	verification_status: "none" | "pending" | "verified";
	challenge_nonce: string | null;
	pinned_public_key: string | null;
	project_id: string | null;
}

export interface ProjectRecord {
	id: string;
	name: string;
	created_at: string;
}

export interface IntegrationEventRecord {
	id: number;
	repo_id: number;
	client_version: string | null;
	os_platform: string | null;
	runtime_env: string | null;
	is_ci: number;
	client_ip: string | null;
	git_actor: string | null;
	created_at: string;
}

export interface LogRecord {
	id: number;
	repo_id: number;
	chain_content: string;
	block_count: number;
	last_block_hash: string;
	updated_at: string;
}

export interface ArchivedLogRecord {
	id: number;
	repo_id: number;
	epoch_index: number;
	chain_content: string;
	block_count: number;
	last_block_hash: string;
	archived_at: string;
}

export interface PackageCacheRecord {
	package_name: string;
	version: string;
	cached_at: string;
}

export interface RepositoryCandlesticksCacheRecord {
	repo_id: number;
	cached_yaml: string;
	updated_at: string;
}

export interface WebhookRecord {
	id: number;
	repo_id: number;
	url: string;
	secret: string | null;
	created_at: string;
}

/**
 * Initializes the SQLite database and ensures the schema exists.
 */
export function initDb(): void {
	DB_FILE = process.env.DATABASE_FILE
		? path.isAbsolute(process.env.DATABASE_FILE)
			? process.env.DATABASE_FILE
			: path.join(process.cwd(), process.env.DATABASE_FILE)
		: path.join(process.cwd(), "data", "packablock.sqlite");

	db = new Database(DB_FILE, { create: true });

	// Enable foreign keys
	db.run("PRAGMA foreign_keys = ON;");

	// In development mode, watch for file changes in the data directory and update automatically
	if (process.env.NODE_ENV !== "production") {
		const dbDir = path.dirname(DB_FILE);
		try {
			if (!watcher) {
				watcher = watch(dbDir, (eventType, filename) => {
					console.log(
						`[DEV MODE] File change detected in data directory: ${filename} (Event: ${eventType})`,
					);
					if (filename === path.basename(DB_FILE)) {
						console.log(
							`[DEV MODE] Re-initializing database connection to: ${DB_FILE}`,
						);
						try {
							db.close();
						} catch (e) {}
						db = new Database(DB_FILE, { create: true });
						db.run("PRAGMA foreign_keys = ON;");
					}
				});
				console.log(
					`[DEV MODE] Watching for file changes in data directory: ${dbDir}`,
				);
			}
		} catch (err) {
			console.error(`[DEV MODE] Failed to watch data directory: ${err}`);
		}
	}

	// Create Repositories table with premium support
	db.run(`
    CREATE TABLE IF NOT EXISTS repositories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner TEXT NOT NULL,
      repo TEXT NOT NULL,
      registration_token TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      is_premium INTEGER DEFAULT 0,
      verification_status TEXT DEFAULT 'none',
      challenge_nonce TEXT,
      pinned_public_key TEXT,
      UNIQUE(owner, repo)
    );
  `);

	// Migrate older databases missing the premium columns
	try {
		db.run("ALTER TABLE repositories ADD COLUMN is_premium INTEGER DEFAULT 0;");
	} catch (e) {}
	try {
		db.run(
			"ALTER TABLE repositories ADD COLUMN verification_status TEXT DEFAULT 'none';",
		);
	} catch (e) {}
	try {
		db.run("ALTER TABLE repositories ADD COLUMN challenge_nonce TEXT;");
	} catch (e) {}
	try {
		db.run("ALTER TABLE repositories ADD COLUMN pinned_public_key TEXT;");
	} catch (e) {}

	// Create Logs table
	db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      chain_content TEXT NOT NULL,
      block_count INTEGER NOT NULL,
      last_block_hash TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(repo_id)
    );
  `);

	// Create Webhooks table
	db.run(`
    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      secret TEXT,
      created_at TEXT NOT NULL
    );
  `);

	// Create Archived Logs table for key rotations / rollovers
	db.run(`
    CREATE TABLE IF NOT EXISTS archived_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      epoch_index INTEGER NOT NULL,
      chain_content TEXT NOT NULL,
      block_count INTEGER NOT NULL,
      last_block_hash TEXT NOT NULL,
      archived_at TEXT NOT NULL
    );
  `);

	// Create Package Cache table for caching upstream package versions
	db.run(`
    CREATE TABLE IF NOT EXISTS package_cache (
      package_name TEXT PRIMARY KEY,
      version TEXT NOT NULL,
      cached_at TEXT NOT NULL
    );
  `);

	// Create Repository Candlesticks Cache table
	db.run(`
    CREATE TABLE IF NOT EXISTS repository_candlesticks_cache (
      repo_id INTEGER PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
      cached_yaml TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);

	// Create Projects table
	db.run(`
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

	// Link repositories to projects via project_id column migration
	try {
		db.run(
			"ALTER TABLE repositories ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL;",
		);
	} catch (e) {}

	// Create Integration Events table
	db.run(`
    CREATE TABLE IF NOT EXISTS integration_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
      client_version TEXT,
      os_platform TEXT,
      runtime_env TEXT,
      is_ci INTEGER DEFAULT 0,
      client_ip TEXT,
      git_actor TEXT,
      created_at TEXT NOT NULL
    );
  `);

	console.log(`SQLite Database initialized at: ${DB_FILE}`);
}

/**
 * Registers a new repository and stores its token (Standard flow).
 */
export function registerRepository(
	owner: string,
	repo: string,
	token: string,
): RepositoryRecord {
	const now = new Date().toISOString();

	db.run(
		`
    INSERT INTO repositories (owner, repo, registration_token, created_at, is_premium, verification_status)
    VALUES (?, ?, ?, ?, 0, 'none')
    ON CONFLICT(owner, repo) DO UPDATE SET
      registration_token = excluded.registration_token,
      created_at = excluded.created_at,
      is_premium = 0,
      verification_status = 'none';
  `,
		[owner.toLowerCase(), repo.toLowerCase(), token, now],
	);

	const query = db.prepare(
		"SELECT * FROM repositories WHERE owner = ? AND repo = ?",
	);
	const record = query.get(
		owner.toLowerCase(),
		repo.toLowerCase(),
	) as RepositoryRecord;
	return record;
}

/**
 * Registers a premium repository in a pending challenge state.
 */
export function registerPremiumPending(
	owner: string,
	repo: string,
	nonce: string,
	tempToken: string,
): RepositoryRecord {
	const now = new Date().toISOString();

	db.run(
		`
    INSERT INTO repositories (owner, repo, registration_token, created_at, is_premium, verification_status, challenge_nonce)
    VALUES (?, ?, ?, ?, 1, 'pending', ?)
    ON CONFLICT(owner, repo) DO UPDATE SET
      registration_token = excluded.registration_token,
      created_at = excluded.created_at,
      is_premium = 1,
      verification_status = 'pending',
      challenge_nonce = excluded.challenge_nonce;
  `,
		[owner.toLowerCase(), repo.toLowerCase(), tempToken, now, nonce],
	);

	const query = db.prepare(
		"SELECT * FROM repositories WHERE owner = ? AND repo = ?",
	);
	const record = query.get(
		owner.toLowerCase(),
		repo.toLowerCase(),
	) as RepositoryRecord;
	return record;
}

/**
 * Promotes verification status, pins the verified public key, and sets active token.
 */
export function verifyAndActivateRepository(
	repoId: number,
	status: "verified" | "pending" | "none",
	publicKey: string | null,
	activeToken: string,
): void {
	db.run(
		`
    UPDATE repositories 
    SET verification_status = ?, pinned_public_key = ?, registration_token = ?
    WHERE id = ?
  `,
		[status, publicKey, activeToken, repoId],
	);
}

/**
 * Looks up a repository by its registration token.
 */
export function getRepositoryByToken(token: string): RepositoryRecord | null {
	const query = db.prepare(
		"SELECT * FROM repositories WHERE registration_token = ?",
	);
	const record = query.get(token) as RepositoryRecord | null;
	return record;
}

/**
 * Looks up a repository by its database ID.
 */
export function getRepositoryById(id: number): RepositoryRecord | null {
	const query = db.prepare("SELECT * FROM repositories WHERE id = ?");
	const record = query.get(id) as RepositoryRecord | null;
	return record;
}

/**
 * Looks up a repository by its owner and name.
 */
export function getRepositoryByPath(
	owner: string,
	repo: string,
): RepositoryRecord | null {
	const query = db.prepare(
		"SELECT * FROM repositories WHERE owner = ? AND repo = ?",
	);
	const record = query.get(
		owner.toLowerCase(),
		repo.toLowerCase(),
	) as RepositoryRecord | null;
	return record;
}

/**
 * Saves or updates a repository's cryptographically verified package log.
 */
export function saveLog(
	repoId: number,
	chainContent: string,
	blockCount: number,
	lastBlockHash: string,
): LogRecord {
	const now = new Date().toISOString();

	db.run(
		`
    INSERT INTO logs (repo_id, chain_content, block_count, last_block_hash, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(repo_id) DO UPDATE SET
      chain_content = excluded.chain_content,
      block_count = excluded.block_count,
      last_block_hash = excluded.last_block_hash,
      updated_at = excluded.updated_at;
  `,
		[repoId, chainContent, blockCount, lastBlockHash, now],
	);

	const query = db.prepare("SELECT * FROM logs WHERE repo_id = ?");
	const record = query.get(repoId) as LogRecord;
	return record;
}

/**
 * Retrieves the package log record for a repository.
 */
export function getLog(repoId: number): LogRecord | null {
	const query = db.prepare("SELECT * FROM logs WHERE repo_id = ?");
	const record = query.get(repoId) as LogRecord | null;
	return record;
}

/**
 * Adds a new webhook endpoint for a repository.
 */
export function addWebhook(
	repoId: number,
	url: string,
	secret: string | null,
): WebhookRecord {
	const now = new Date().toISOString();
	const result = db.run(
		`
    INSERT INTO webhooks (repo_id, url, secret, created_at)
    VALUES (?, ?, ?, ?);
  `,
		[repoId, url, secret, now],
	);

	const recordId = result.lastInsertRowid as number;
	const query = db.prepare("SELECT * FROM webhooks WHERE id = ?");
	return query.get(recordId) as WebhookRecord;
}

/**
 * Lists all registered webhooks for a repository.
 */
export function getWebhooks(repoId: number): WebhookRecord[] {
	const query = db.prepare("SELECT * FROM webhooks WHERE repo_id = ?");
	return query.all(repoId) as WebhookRecord[];
}

/**
 * Deletes a registered webhook for a repository.
 */
export function deleteWebhook(id: number, repoId: number): boolean {
	const result = db.run("DELETE FROM webhooks WHERE id = ? AND repo_id = ?;", [
		id,
		repoId,
	]);
	return result.changes > 0;
}

/**
 * Archives a repository's current active package log during key rollover.
 */
export function archiveLog(
	repoId: number,
	chainContent: string,
	blockCount: number,
	lastBlockHash: string,
): void {
	const now = new Date().toISOString();

	// Calculate next epoch index (how many logs are already archived for this repo)
	const countQuery = db.prepare(
		"SELECT COUNT(*) as count FROM archived_logs WHERE repo_id = ?",
	);
	const countResult = countQuery.get(repoId) as { count: number };
	const nextEpochIndex = countResult.count;

	db.run(
		`
    INSERT INTO archived_logs (repo_id, epoch_index, chain_content, block_count, last_block_hash, archived_at)
    VALUES (?, ?, ?, ?, ?, ?);
  `,
		[repoId, nextEpochIndex, chainContent, blockCount, lastBlockHash, now],
	);
}

/**
 * Retrieves all archived package logs for a repository sorted by epoch index.
 */
export function getArchivedLogs(repoId: number): ArchivedLogRecord[] {
	const query = db.prepare(
		"SELECT * FROM archived_logs WHERE repo_id = ? ORDER BY epoch_index ASC;",
	);
	return query.all(repoId) as ArchivedLogRecord[];
}

/**
 * Retrieves a cached package version if it exists and is within TTL.
 */
export function getCachedPackage(
	packageName: string,
	ttlMs: number,
): string | null {
	const query = db.prepare(
		"SELECT * FROM package_cache WHERE package_name = ?;",
	);
	const record = query.get(packageName) as PackageCacheRecord | null;
	if (record) {
		const age = Date.now() - new Date(record.cached_at).getTime();
		if (age < ttlMs) {
			return record.version;
		}
	}
	return null;
}

export function getCachedPackageRecord(
	packageName: string,
): PackageCacheRecord | null {
	const query = db.prepare(
		"SELECT * FROM package_cache WHERE package_name = ?;",
	);
	return query.get(packageName) as PackageCacheRecord | null;
}

/**
 * Caches or updates an upstream package version.
 */
export function saveCachedPackage(packageName: string, version: string): void {
	const now = new Date().toISOString();
	db.run(
		`
    INSERT INTO package_cache (package_name, version, cached_at)
    VALUES (?, ?, ?)
    ON CONFLICT(package_name) DO UPDATE SET
      version = excluded.version,
      cached_at = excluded.cached_at;
  `,
		[packageName, version, now],
	);
}

/**
 * Creates a new project and returns its record.
 */
export function createProject(name: string): ProjectRecord {
	const id = crypto.randomUUID();
	const now = new Date().toISOString();
	db.run("INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)", [
		id,
		name,
		now,
	]);
	return { id, name, created_at: now };
}

/**
 * Groups/links a repository to a project.
 */
export function linkRepoToProject(
	repoId: number,
	projectId: string | null,
): void {
	db.run("UPDATE repositories SET project_id = ? WHERE id = ?", [
		projectId,
		repoId,
	]);
}

/**
 * Lists all projects with their mapped repository counts.
 */
export function getProjects(): Array<ProjectRecord & { repoCount: number }> {
	const query = db.prepare(`
		SELECT p.*, COUNT(r.id) as repoCount
		FROM projects p
		LEFT JOIN repositories r ON r.project_id = p.id
		GROUP BY p.id
		ORDER BY p.name ASC
	`);
	return query.all() as any;
}

/**
 * Retrieves specific project details.
 */
export function getProjectDetails(projectId: string): ProjectRecord | null {
	const query = db.prepare("SELECT * FROM projects WHERE id = ?");
	return query.get(projectId) as ProjectRecord | null;
}

/**
 * Lists all repositories mapped to a specific project.
 */
export function getProjectRepos(projectId: string): Array<RepositoryRecord> {
	const query = db.prepare(
		"SELECT * FROM repositories WHERE project_id = ? ORDER BY owner ASC, repo ASC",
	);
	return query.all(projectId) as any;
}

/**
 * Records client execution metadata on log pushes.
 */
export function logIntegrationEvent(
	repoId: number,
	metadata: {
		client_version: string | null;
		os_platform: string | null;
		runtime_env: string | null;
		is_ci: number;
		client_ip: string | null;
		git_actor: string | null;
	},
): void {
	const now = new Date().toISOString();
	db.run(
		`
		INSERT INTO integration_events (repo_id, client_version, os_platform, runtime_env, is_ci, client_ip, git_actor, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`,
		[
			repoId,
			metadata.client_version,
			metadata.os_platform,
			metadata.runtime_env,
			metadata.is_ci,
			metadata.client_ip,
			metadata.git_actor,
			now,
		],
	);
}

/**
 * Fetches recent integration events for a repository.
 */
export function getIntegrationEvents(
	repoId: number,
): Array<IntegrationEventRecord> {
	const query = db.prepare(
		"SELECT * FROM integration_events WHERE repo_id = ? ORDER BY created_at DESC LIMIT 50",
	);
	return query.all(repoId) as any;
}

/**
 * Lists all repositories in the registry database.
 */
export function getAllRepos(): Array<RepositoryRecord> {
	const query = db.prepare(
		"SELECT * FROM repositories ORDER BY owner ASC, repo ASC",
	);
	return query.all() as any;
}

/**
 * Admin action to toggle repository premium tier.
 */
export function togglePremium(repoId: number): void {
	const query = db.prepare("SELECT is_premium FROM repositories WHERE id = ?");
	const record = query.get(repoId) as { is_premium: number } | null;
	if (record) {
		const newPremium = record.is_premium === 1 ? 0 : 1;
		const newStatus = newPremium === 1 ? "verified" : "none";
		db.run(
			"UPDATE repositories SET is_premium = ?, verification_status = ? WHERE id = ?",
			[newPremium, newStatus, repoId],
		);
	}
}

/**
 * Admin action to revoke repository registration token.
 */
export function revokeRepositoryToken(repoId: number): void {
	const revokedToken = "pb_revoked_" + crypto.randomUUID();
	db.run("UPDATE repositories SET registration_token = ? WHERE id = ?", [
		revokedToken,
		repoId,
	]);
}

/**
 * Admin action to garbage collect unverified repositories in pending status.
 */
export function purgeStaleRepositories(): number {
	const result = db.run(
		"DELETE FROM repositories WHERE verification_status = 'pending'",
	);
	return result.changes;
}

/**
 * Gets cached candlesticks YAML representation for a repository.
 */
export function getCachedCandlesticks(
	repoId: number,
): RepositoryCandlesticksCacheRecord | null {
	const query = db.prepare(
		"SELECT * FROM repository_candlesticks_cache WHERE repo_id = ?;",
	);
	return query.get(repoId) as RepositoryCandlesticksCacheRecord | null;
}

/**
 * Caches or updates candlesticks YAML representation for a repository.
 */
export function saveCachedCandlesticks(
	repoId: number,
	cachedYaml: string,
): void {
	const now = new Date().toISOString();
	db.run(
		`
    INSERT INTO repository_candlesticks_cache (repo_id, cached_yaml, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT(repo_id) DO UPDATE SET
      cached_yaml = excluded.cached_yaml,
      updated_at = excluded.updated_at;
  `,
		[repoId, cachedYaml, now],
	);
}
