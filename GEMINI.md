# GEMINI.md: Multi-Agent Identity & Configuration Guidelines

This workspace orchestrates a zero-trust package attestation log. To prevent credential clashing and ensure absolute audit trail integrity across our **multi-agent team**, all AI agents and subagents working in this workspace must strictly adhere to these dynamic authorization boundaries.

---

## 🔑 Agent Identity & Git Commit Signing

When creating Git commits or performing Git history modifications, agents must **never** use the human developer's global VM configurations (`user.name "Aaron Bronow"`). 

Instead, each agent must resolve its unique cryptographic identity and override the configuration dynamically for every Git transaction:

1. **Load Environment**: Source the `.env` file in the root workspace `/home/aaron/dev/packablock/.env`.
2. **Resolve Identity**: Map your assigned role to its corresponding environment variables (e.g. for `Agy` role, load `AGY_GITHUB_NAME`, `AGY_GITHUB_EMAIL`, and `AGY_GITHUB_SIGNING_KEY`).
3. **Dynamic Overrides**: Prefix your Git commit commands with your resolved environment parameters:

```bash
git \
  -c user.name="$<YOUR_ROLE>_GITHUB_NAME" \
  -c user.email="$<YOUR_ROLE>_GITHUB_EMAIL" \
  -c user.signingkey="$<YOUR_ROLE>_GITHUB_SIGNING_KEY" \
  -c gpg.format=ssh \
  -c commit.gpgsign=true \
  commit -m "Your commit message"
```

---

## 🌐 GitHub API & Push Authentication

The human owner (`aaronbronow`) maintains global terminal session authorization. Do **not** overwrite or log out of the global `gh auth login` state.

To perform remote Git pushes or execute GitHub CLI (`gh`) API requests on behalf of a specific agent:
1. **Load Environment**: Source the `.env` file in the root workspace `/home/aaron/dev/packablock/.env`.
2. **Resolve Token**: Dynamically fetch the personal access token (PAT) assigned to your specific role:
   * **Agy**: `AGY_GITHUB_TOKEN`
   * **Contributor 1**: `CONTRIBUTOR_1_GITHUB_TOKEN`
   * **Contributor 2**: `CONTRIBUTOR_2_GITHUB_TOKEN`
   * **Planner**: `PLANNER_GITHUB_TOKEN`
   * **Tester**: `TESTER_GITHUB_TOKEN`
3. **Push Authentication**: Prefix all Git pushes or GitHub API calls with your token to force basic authentication, preventing credential caching conflicts with the human owner:

### 🚀 Git Push Overrides
```bash
GITHUB_TOKEN=$<YOUR_ROLE_GITHUB_TOKEN> git push origin <branch>
```

### 🔍 GitHub API Overrides
```bash
GH_TOKEN=$<YOUR_ROLE_GITHUB_TOKEN> gh api <endpoint>
```

---

## 🛠️ Workspace Architecture Mapping
* **`packablock-client`**: Bun CLI client that automatically reads the local config and pushes cryptographically verified logs to `/api/v1/log/push`.
* **`packablock-api`**: Fastify SQLite server listening locally on port `3030`. Processes log checks, verifies OIDC runner attestations, and dynamically authorizes contributors.
