# packablock-registry (Packablock Supply Chain Trust Registry)

The registry server component for Packablock. It receives, verifies, stores, and audits cryptographic package attestation chains pushed by the Packablock client.

<img width="128" height="128" alt="packablock-registry-avatar-512" src="https://github.com/user-attachments/assets/38f97ec9-3e72-49e5-b98b-2c0555a760ac" />

---

## 📋 Features

- **Zero-Trust Package Attestation**: Verifies the cryptographic hashes and integrity signatures of pushed package chains.
- **Parallel Multi-Lockfile Tracking**: Tracks multiple lockfiles (e.g., `package-lock.json`, `bun.lockb`, `pnpm-lock.yaml`) in parallel within a single repository chain.
- **Chain Life-Cycle Events**: Supports dynamic addition and removal of lockfiles mid-chain using `init` and `forget` events.
- **SemVer Drift Detection**: Analyzes package diffs across blocks to alert on version regressions, high drift velocity, and custom security policies.
- **Webhook Integration**: Dispatches outbound event alerts to integrated tools (e.g., Windmill, Slack, GitHub webhooks).

---

## 💾 Attestation Chain Data Format

The registry parses block payloads using a nested, multi-lockfile format. Each lockfile in the repository is represented by its own root key containing its packages and state.

### 1. Lockfile Initialization (`init` event)
To start tracking a new lockfile or re-initialize one, include a `chain_event: init` metadata field and the complete list of packages:

```yaml
package-lock.json:
  chain_event: init
  packages:
    - lodash: "4.17.21"
    - express: "4.18.2"
```

### 2. Lockfile Updates (Diff Format)
Subsequent blocks contain version differences for individual lockfiles rather than full package lists. The registry aggregates these diffs to maintain the current active package manifest state:

```yaml
package-lock.json:
  packages:
    - lodash: [{ old: "4.17.21" }, { new: "4.17.22" }]
    - debug: [{ new: "4.3.4" }]
```

### 3. Lockfile Removal (`forget` event)
To stop tracking a lockfile entirely and clear it from the repository's active package database state, send a `chain_event: forget` event:

```yaml
package-lock.json:
  chain_event: forget
```

---

## 🛠️ API Documentation

### Public Audit Endpoints

#### 1. `GET /api/v1/repo/:owner/:repo/history`
Retrieves the full chronological audit trail of blocks.
- **Response**:
  ```json
  {
    "success": true,
    "history": [
      {
        "block_index": 0,
        "timestamp": "2026-06-03T16:25:35Z",
        "data_hash": "...",
        "meta_hash": "...",
        "packages": {
          "package-lock.json": {
            "chain_event": "init",
            "packages": [
              { "lodash": "4.17.21" }
            ]
          }
        }
      }
    ]
  }
  ```

#### 2. `GET /api/v1/repo/:owner/:repo/tree`
Retrieves a JSON representation of the visualization tree and flat graph representing the package chain blocks.
- **Response**:
  ```json
  {
    "success": true,
    "repository": "owner/repo",
    "blockCount": 2,
    "tree": {
      "id": "genesis_anchor_hash",
      "name": "Genesis Anchor",
      "type": "root",
      "children": [...]
    },
    "graph": {
      "nodes": [
        {
          "id": "genesis_anchor_hash",
          "label": "Genesis Anchor",
          "type": "root"
        },
        {
          "id": "block_hash_1",
          "label": "Block #0",
          "type": "block",
          "packagesCount": 1
        }
      ],
      "links": [
        { "source": "genesis_anchor_hash", "target": "block_hash_1" }
      ]
    }
  }
  ```

---

## 🚀 Getting Started

### Installation
Ensure you have [Bun](https://bun.sh) installed.

```bash
bun install
```

### Running the Server
```bash
bun run index.ts
```

### Running Tests
The registry test suite contains comprehensive coverage for parallel lockfiles, SemVer checking, and webhooks.

```bash
bun test
```
