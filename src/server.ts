import fastify from 'fastify';
import { randomBytes } from 'node:crypto';
import { 
  initDb, 
  registerRepository, 
  getRepositoryByToken, 
  getRepositoryByPath, 
  saveLog, 
  getLog 
} from './database.js';
import { verifyInMemoryChain } from './verify.js';
import { verifyGithubOidcToken } from './oidc.js';

const server = fastify({ logger: true });

// Register content type parser for plain text / YAML payloads
server.addContentTypeParser(['text/yaml', 'application/yaml', 'text/plain'], { parseAs: 'string' }, function (req, body, done) {
  done(null, body);
});

/**
 * Health check endpoint
 */
server.get('/health', async () => {
  return { status: 'ok', service: 'packablock-api' };
});

/**
 * Register a new repository. Returns a registration token.
 */
server.post('/api/v1/repos/register', async (request, reply) => {
  const body = request.body as any;
  if (!body || !body.owner || !body.repo) {
    return reply.status(400).send({ 
      error: 'Bad Request', 
      message: 'Fields "owner" and "repo" are required in request body.' 
    });
  }

  const { owner, repo } = body;
  
  // Generate a cryptographically secure random registration token
  const token = 'pb_reg_' + randomBytes(24).toString('hex');
  
  try {
    const record = registerRepository(owner, repo, token);
    return {
      success: true,
      owner: record.owner,
      repo: record.repo,
      registrationToken: record.registration_token,
      message: 'Repository registered successfully. Store this token in your secrets!'
    };
  } catch (err: any) {
    request.log.error(err);
    return reply.status(500).send({ 
      error: 'Internal Server Error', 
      message: err.message 
    });
  }
});

/**
 * Push cryptographically verified package chain to the database.
 * Supports metadata-free endpoints and dynamic Developer/CI authentication.
 */
server.post('/api/v1/log/push', async (request, reply) => {
  const chainContent = request.body as string;
  if (!chainContent || typeof chainContent !== 'string') {
    return reply.status(400).send({ 
      error: 'Bad Request', 
      message: 'Package chain content must be sent as raw YAML body.' 
    });
  }

  // Extract auth headers
  const authHeader = request.headers['authorization'];
  const repoTokenHeader = request.headers['x-repo-token'] as string | undefined;
  const oidcTokenHeader = request.headers['x-github-oidc-token'] as string | undefined;
  const targetRepoHeader = request.headers['x-target-repo'] as string | undefined; // Required for local OAuth developer pushes

  let resolvedRepo: { id: number; owner: string; repo: string } | null = null;
  let authType: 'ci' | 'developer' = 'ci';

  // 1. Resolve Authorization Token (CI registration token vs Developer personal OAuth token)
  let token = '';
  if (repoTokenHeader) {
    token = repoTokenHeader;
  } else if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }

  if (!token) {
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Authentication required. Provide "X-Repo-Token" or "Authorization: Bearer <token>" header.'
    });
  }

  // Check if token exists in SQLite database as a registration token (CI Flow)
  const dbRepo = getRepositoryByToken(token);
  
  if (dbRepo) {
    resolvedRepo = dbRepo;
    authType = 'ci';
    
    // Enforce GitHub OIDC Verification if the OIDC token is supplied in the headers
    if (oidcTokenHeader) {
      const repoPath = `${dbRepo.owner}/${dbRepo.repo}`;
      request.log.info(`Verifying GitHub Actions OIDC Token for repo: ${repoPath}`);
      const oidcResult = await verifyGithubOidcToken(oidcTokenHeader, repoPath);
      
      if (!oidcResult.valid) {
        return reply.status(403).send({
          error: 'Forbidden',
          message: `CI OIDC Token Verification Failed: ${oidcResult.reason}`
        });
      }
      request.log.info(`OIDC Signature successfully validated for runner actor: ${oidcResult.payload?.actor}`);
    }
  } else {
    // Treat as personal GitHub OAuth Token (Developer Flow)
    authType = 'developer';
    
    if (!targetRepoHeader) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Personal OAuth push requires "X-Target-Repo: owner/repo" header to authorize collaboration write permissions.'
      });
    }

    const [owner, repo] = targetRepoHeader.split('/');
    if (!owner || !repo) {
      return reply.status(400).send({
        error: 'Bad Request',
        message: 'Invalid "X-Target-Repo" format. Must be "owner/repo".'
      });
    }

    // Call GitHub API to identify the user
    request.log.info('Contacting GitHub API to identify local developer...');
    const userRes = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Packablock-API'
      }
    });

    if (!userRes.ok) {
      return reply.status(401).send({
        error: 'Unauthorized',
        message: 'GitHub OAuth token is invalid or expired.'
      });
    }

    const userData: any = await userRes.json();
    const username = userData.login;
    request.log.info(`Authenticated GitHub developer: ${username}`);

    // Call GitHub API to verify collaborator permissions
    request.log.info(`Checking write permissions for developer ${username} on ${targetRepoHeader}...`);
    const permRes = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/collaborators/${username}/permission`,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'Packablock-API'
        }
      }
    );

    if (!permRes.ok) {
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Failed to fetch repository collaborator permissions from GitHub. Verify repository path: ${targetRepoHeader}`
      });
    }

    const permData: any = await permRes.json();
    const permission = permData.permission; // e.g. "admin", "write", "read", "none"
    request.log.info(`Developer permission level: ${permission}`);

    if (permission !== 'admin' && permission !== 'write') {
      return reply.status(403).send({
        error: 'Forbidden',
        message: `Insufficient permissions. Developer "${username}" requires "write" or "admin" permission on "${targetRepoHeader}". Got "${permission}".`
      });
    }

    // User is authorized! Ensure repo exists in SQLite database, registering automatically if needed.
    let repoRecord = getRepositoryByPath(owner, repo);
    if (!repoRecord) {
      // Auto-register since collaborator possesses write permissions on GitHub
      request.log.info(`Repository "${targetRepoHeader}" not in database. Auto-registering...`);
      const autoToken = 'pb_reg_' + randomBytes(24).toString('hex');
      repoRecord = registerRepository(owner, repo, autoToken);
    }
    
    resolvedRepo = repoRecord;
  }

  if (!resolvedRepo) {
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Token lookup or contributor authorization failed.'
    });
  }

  // 2. Cryptographically verify the in-memory chain
  request.log.info(`Verifying chain cryptographic hashes for repository ID: ${resolvedRepo.id}`);
  const report = verifyInMemoryChain(chainContent);

  if (!report.valid) {
    return reply.status(422).send({
      error: 'Unprocessable Entity',
      message: 'Chain cryptographic verification failed.',
      details: {
        reason: report.reason,
        blockIndex: report.blockIndex,
        tamperedComponent: report.tamperedComponent,
        expected: report.expected,
        actual: report.actual
      }
    });
  }

  // 3. Save the validated chain into SQLite
  try {
    const saved = saveLog(resolvedRepo.id, chainContent, report.blockCount!, report.lastBlockHash!);
    request.log.info(`Successfully stored log for "${resolvedRepo.owner}/${resolvedRepo.repo}". Total blocks: ${report.blockCount}`);
    
    return {
      success: true,
      message: 'Package history pushed and validated successfully.',
      authType,
      repository: `${resolvedRepo.owner}/${resolvedRepo.repo}`,
      blockCount: saved.block_count,
      lastBlockHash: saved.last_block_hash,
      updatedAt: saved.updated_at
    };
  } catch (err: any) {
    request.log.error(err);
    return reply.status(500).send({
      error: 'Internal Server Error',
      message: `Failed to save log history to database: ${err.message}`
    });
  }
});

/**
 * Pull cryptographically verified package chain from the database.
 * Supports metadata-free requests (token or owner/repo header lookup).
 */
server.get('/api/v1/log/pull', async (request, reply) => {
  const tokenHeader = request.headers['x-repo-token'] as string | undefined;
  const authHeader = request.headers['authorization'];
  const targetRepoHeader = request.headers['x-target-repo'] as string | undefined;

  let resolvedRepo: { id: number; owner: string; repo: string } | null = null;

  let token = '';
  if (tokenHeader) {
    token = tokenHeader;
  } else if (authHeader && authHeader.startsWith('Bearer ')) {
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
    const [owner, repo] = targetRepoHeader.split('/');
    if (owner && repo) {
      resolvedRepo = getRepositoryByPath(owner, repo);
    }
  }

  if (!resolvedRepo) {
    return reply.status(404).send({
      error: 'Not Found',
      message: 'Repository not found or access token unauthorized.'
    });
  }

  const logRecord = getLog(resolvedRepo.id);
  if (!logRecord) {
    return reply.status(404).send({
      error: 'Not Found',
      message: `No log initialized for repository "${resolvedRepo.owner}/${resolvedRepo.repo}" yet.`
    });
  }

  reply.header('Content-Type', 'text/yaml');
  return logRecord.chain_content;
});

/**
 * Starts the server on the specified port.
 */
export async function startServer(port = 3000): Promise<void> {
  // Initialize database schema
  initDb();
  
  try {
    await server.listen({ port, host: '0.0.0.0' });
    console.log(`🚀 Packablock API Server successfully listening on http://localhost:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}
