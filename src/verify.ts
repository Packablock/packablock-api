import { createHash } from 'node:crypto';
import YAML from 'yaml';

export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export interface ChainMeta {
  version: string;
  block_index: number;
  timestamp: string;
  hashing_strategy: 'raw';
  data_hash: string;
  prev_meta_hash: string;
  meta_hash?: string;
  [key: string]: any;
}

export interface VerificationReport {
  valid: boolean;
  reason?: string;
  blockIndex?: number;
  tamperedComponent?: 'data' | 'meta' | 'chain' | 'index' | 'structure';
  expected?: any;
  actual?: any;
  lastBlockHash?: string;
  blockCount?: number;
}

/**
 * Computes SHA-256 hash.
 */
export function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Recursively sorts keys and computes metadata block hash.
 */
export function deterministicMetaHash(meta: Record<string, any>): string {
  const { meta_hash, ...rest } = meta;
  const sortedKeys = Object.keys(rest).sort();
  const sortedObj: Record<string, any> = {};
  for (const key of sortedKeys) {
    const val = rest[key];
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      sortedObj[key] = sortKeysObject(val);
    } else {
      sortedObj[key] = val;
    }
  }
  return sha256(JSON.stringify(sortedObj));
}

function sortKeysObject(obj: Record<string, any>): Record<string, any> {
  const sorted: Record<string, any> = {};
  for (const key of Object.keys(obj).sort()) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      sorted[key] = sortKeysObject(val);
    } else {
      sorted[key] = val;
    }
  }
  return sorted;
}

/**
 * Splits log content into documents.
 */
export function splitRawDocuments(fileContent: string): string[] {
  if (!fileContent || !fileContent.trim()) {
    return [];
  }
  const lines = fileContent.split(/\r?\n/);
  const docs: string[] = [];
  let currentDoc: string[] = [];
  
  for (const line of lines) {
    if (/^---\s*$/.test(line)) {
      if (currentDoc.length > 0 || docs.length > 0) {
        docs.push(currentDoc.join('\n'));
        currentDoc = [];
      }
    } else {
      currentDoc.push(line);
    }
  }
  
  docs.push(currentDoc.join('\n'));
  return docs;
}

/**
 * Cryptographically verifies a single document pair in-memory.
 */
function verifySingleBlock(
  i: number, 
  dataDocStr: string, 
  metaDocStr: string, 
  expectedPrevHash: string
): VerificationReport {
  let parsed;
  try {
    parsed = YAML.parse(metaDocStr);
  } catch (e: any) {
    return {
      valid: false,
      reason: `Failed to parse metadata document at block ${i} as valid YAML.`,
      blockIndex: i,
      tamperedComponent: 'meta'
    };
  }
  
  const meta = parsed?.['$yaml-chain-meta'];
  if (!meta) {
    return {
      valid: false,
      reason: `Metadata document at block ${i} is missing the '$yaml-chain-meta' root key.`,
      blockIndex: i,
      tamperedComponent: 'meta'
    };
  }
  
  // 1. Verify index
  if (meta.block_index !== i) {
    return {
      valid: false,
      reason: `Block index mismatch at block ${i}: metadata says index is ${meta.block_index}.`,
      blockIndex: i,
      tamperedComponent: 'index',
      expected: i,
      actual: meta.block_index
    };
  }
  
  // 2. Verify prev hash
  if (meta.prev_meta_hash !== expectedPrevHash) {
    let isRollover = false;
    if (i === 0) {
      try {
        const parsedData = YAML.parse(dataDocStr);
        if (parsedData?.genesis_rollover) {
          isRollover = true;
        }
      } catch (e) {
        // Ignored
      }
    }
    
    if (isRollover) {
      if (!/^[0-9a-fA-F]{64}$/.test(meta.prev_meta_hash)) {
        return {
          valid: false,
          reason: `Invalid rollover prev_meta_hash format at block ${i}: expected 64-character SHA-256 hash, but found '${meta.prev_meta_hash}'.`,
          blockIndex: i,
          tamperedComponent: 'chain'
        };
      }
    } else {
      return {
        valid: false,
        reason: `Chain link broken at block ${i}: expected prev_meta_hash to be '${expectedPrevHash}', but found '${meta.prev_meta_hash}'.`,
        blockIndex: i,
        tamperedComponent: 'chain',
        expected: expectedPrevHash,
        actual: meta.prev_meta_hash
      };
    }
  }
  
  // 3. Verify data hash
  const computedDataHash = sha256(dataDocStr.trim());
  if (meta.data_hash !== computedDataHash) {
    return {
      valid: false,
      reason: `Cryptographic mismatch in data payload at block ${i}: calculated hash is '${computedDataHash}', but metadata signature has '${meta.data_hash}'.`,
      blockIndex: i,
      tamperedComponent: 'data',
      expected: meta.data_hash,
      actual: computedDataHash
    };
  }
  
  // 4. Verify meta signature
  const computedMetaHash = deterministicMetaHash(meta);
  if (meta.meta_hash !== computedMetaHash) {
    return {
      valid: false,
      reason: `Cryptographic mismatch in metadata signature itself at block ${i}: calculated signature is '${computedMetaHash}', but block contains '${meta.meta_hash}'.`,
      blockIndex: i,
      tamperedComponent: 'meta',
      expected: computedMetaHash,
      actual: meta.meta_hash
    };
  }

  return { valid: true, lastBlockHash: meta.meta_hash };
}

/**
 * Validates a complete package chain/log string in-memory.
 */
export function verifyInMemoryChain(chainContent: string): VerificationReport {
  const docs = splitRawDocuments(chainContent);
  if (docs.length === 0) {
    return { valid: false, reason: 'Chain content is empty.', tamperedComponent: 'structure' };
  }
  
  if (docs.length % 2 !== 0) {
    return {
      valid: false,
      reason: `Chain structure is malformed. Expected pairs of [data, meta] documents, but found ${docs.length} total documents.`,
      tamperedComponent: 'structure'
    };
  }
  
  const blockCount = docs.length / 2;
  let expectedPrevHash = GENESIS_PREV_HASH;
  let lastBlockHash = '';

  for (let i = 0; i < blockCount; i++) {
    const dataDocStr = docs[2 * i];
    const metaDocStr = docs[2 * i + 1];
    
    const blockReport = verifySingleBlock(i, dataDocStr, metaDocStr, expectedPrevHash);
    if (!blockReport.valid) {
      return blockReport;
    }
    
    expectedPrevHash = blockReport.lastBlockHash!;
    lastBlockHash = blockReport.lastBlockHash!;
  }

  return { 
    valid: true, 
    lastBlockHash,
    blockCount 
  };
}
