import { Database } from 'bun:sqlite';
import path from 'node:path';

const DB_FILE = path.join(process.cwd(), 'packablock.sqlite');

let db: Database;

export interface RepositoryRecord {
  id: number;
  owner: string;
  repo: string;
  registration_token: string;
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

/**
 * Initializes the SQLite database and ensures the schema exists.
 */
export function initDb(): void {
  db = new Database(DB_FILE, { create: true });
  
  // Enable foreign keys
  db.run('PRAGMA foreign_keys = ON;');
  
  // Create Repositories table
  db.run(`
    CREATE TABLE IF NOT EXISTS repositories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner TEXT NOT NULL,
      repo TEXT NOT NULL,
      registration_token TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(owner, repo)
    );
  `);
  
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

  console.log(`SQLite Database initialized at: ${DB_FILE}`);
}

/**
 * Registers a new repository and stores its token.
 */
export function registerRepository(owner: string, repo: string, token: string): RepositoryRecord {
  const now = new Date().toISOString();
  
  db.run(`
    INSERT INTO repositories (owner, repo, registration_token, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(owner, repo) DO UPDATE SET
      registration_token = excluded.registration_token,
      created_at = excluded.created_at;
  `, [owner.toLowerCase(), repo.toLowerCase(), token, now]);

  const query = db.prepare('SELECT * FROM repositories WHERE owner = ? AND repo = ?');
  const record = query.get(owner.toLowerCase(), repo.toLowerCase()) as RepositoryRecord;
  return record;
}

/**
 * Looks up a repository by its registration token.
 */
export function getRepositoryByToken(token: string): RepositoryRecord | null {
  const query = db.prepare('SELECT * FROM repositories WHERE registration_token = ?');
  const record = query.get(token) as RepositoryRecord | null;
  return record;
}

/**
 * Looks up a repository by its owner and name.
 */
export function getRepositoryByPath(owner: string, repo: string): RepositoryRecord | null {
  const query = db.prepare('SELECT * FROM repositories WHERE owner = ? AND repo = ?');
  const record = query.get(owner.toLowerCase(), repo.toLowerCase()) as RepositoryRecord | null;
  return record;
}

/**
 * Saves or updates a repository's cryptographically verified package log.
 */
export function saveLog(
  repoId: number, 
  chainContent: string, 
  blockCount: number, 
  lastBlockHash: string
): LogRecord {
  const now = new Date().toISOString();
  
  db.run(`
    INSERT INTO logs (repo_id, chain_content, block_count, last_block_hash, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(repo_id) DO UPDATE SET
      chain_content = excluded.chain_content,
      block_count = excluded.block_count,
      last_block_hash = excluded.last_block_hash,
      updated_at = excluded.updated_at;
  `, [repoId, chainContent, blockCount, lastBlockHash, now]);

  const query = db.prepare('SELECT * FROM logs WHERE repo_id = ?');
  const record = query.get(repoId) as LogRecord;
  return record;
}

/**
 * Retrieves the package log record for a repository.
 */
export function getLog(repoId: number): LogRecord | null {
  const query = db.prepare('SELECT * FROM logs WHERE repo_id = ?');
  const record = query.get(repoId) as LogRecord | null;
  return record;
}
