# GEMINI.md: Multi-Agent Identity & Configuration Guidelines

This workspace orchestrates a zero-trust package attestation log. To prevent credential clashing and ensure absolute audit trail integrity across our **multi-agent team**, all AI agents and subagents working in this workspace must strictly adhere to these dynamic authorization boundaries.

---

## 🔑 Agent Identity & Git Commit Signing

When creating Git commits or performing Git history modifications, agents must **never** use the human developer's global VM configurations (`user.name "Aaron Bronow"`). 

Instead, each agent must resolve its unique cryptographic identity and override the configuration dynamically for every Git transaction:

1. **Load Environment**: Source the role-specific `.env.<role>` file in the root workspace (e.g. `/home/aaron/dev/packablock/.env.agy` or `/home/aaron/dev/packablock/.env.contributor-1`).
2. **Resolve Identity**: The keys are standardized in every file (`GITHUB_NAME`, `GITHUB_EMAIL`, `GITHUB_SIGNING_KEY`).
3. **Dynamic Overrides**: Prefix your Git commit commands with your resolved environment parameters:

```bash
git \
  -c user.name="$GITHUB_NAME" \
  -c user.email="$GITHUB_EMAIL" \
  -c user.signingkey="$GITHUB_SIGNING_KEY" \
  -c gpg.format=ssh \
  -c commit.gpgsign=true \
  commit -m "Your commit message"
```

---

## 🌐 GitHub API & Push Authentication

The human owner (`aaronbronow`) maintains global terminal session authorization. Do **not** overwrite or log out of the global `gh auth login` state.

To perform remote Git pushes or execute GitHub CLI (`gh`) API requests on behalf of a specific agent:
1. **Load Environment**: Source the role-specific `.env.<role>` file in the root workspace.
2. **Resolve Token**: Standardized as `GITHUB_TOKEN` in every agent's profile.
3. **Push Authentication**: Prefix all Git pushes or GitHub API calls with your token to force basic authentication, preventing credential caching conflicts with the human owner:

### 🚀 Git Push Overrides
```bash
GITHUB_TOKEN=$GITHUB_TOKEN git push origin <branch>
```

### 🔍 GitHub API Overrides
```bash
GH_TOKEN=$GITHUB_TOKEN gh api <endpoint>
```

---

## 🛠️ Workspace Architecture Mapping
* **`packablock-client`**: Bun CLI client that automatically reads the local config and pushes cryptographically verified logs to `/api/v1/log/push`.
* **`packablock-api`**: Fastify SQLite server listening locally on port `3030`. Processes log checks, verifies OIDC runner attestations, and dynamically authorizes contributors.
