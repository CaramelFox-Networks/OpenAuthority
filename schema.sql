-- Certificate Authorities table
CREATE TABLE IF NOT EXISTS certificate_authorities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_sha512 TEXT UNIQUE NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    pem_data TEXT NOT NULL,
    name_constraints_dns TEXT NOT NULL,
    name_constraints_ip TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    last_check_at TEXT NOT NULL,
    status TEXT DEFAULT 'probationary' CHECK(status IN ('active', 'probationary', 'revoked', 'expired')),
    consecutive_failures INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    successful_verification_count INTEGER DEFAULT 0
);

-- Verification log for audit trail
CREATE TABLE IF NOT EXISTS verification_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ca_id INTEGER NOT NULL,
  check_type TEXT NOT NULL,
  target TEXT NOT NULL,
  success INTEGER NOT NULL,
  details TEXT,
  checked_at TEXT NOT NULL,
  nonce TEXT,
  leaf_hash TEXT,
  tree_position INTEGER,
  FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id)
);

CREATE TABLE IF NOT EXISTS transparency_checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tree_size INTEGER NOT NULL,
  root_hash TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  signature TEXT,
  previous_checkpoint_hash TEXT NOT NULL,
  checkpoint_hash TEXT NOT NULL UNIQUE,
  external_anchors TEXT,
  consistency_proof TEXT,
  rekor_entry_uuid TEXT,
  rekor_log_index INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE merkle_nodes (
  level INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  hash TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (level, idx)
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_ca_status ON certificate_authorities(status);
CREATE INDEX IF NOT EXISTS idx_ca_fingerprint ON certificate_authorities(fingerprint_sha512);
CREATE INDEX IF NOT EXISTS idx_ca_last_check ON certificate_authorities(last_check_at);
CREATE INDEX IF NOT EXISTS idx_checkpoints_hash ON transparency_checkpoints(checkpoint_hash);
CREATE INDEX IF NOT EXISTS idx_checkpoints_timestamp ON transparency_checkpoints(timestamp);
CREATE INDEX IF NOT EXISTS idx_log_tree_position ON verification_log(tree_position);
CREATE INDEX IF NOT EXISTS idx_log_leaf_hash ON verification_log(leaf_hash);
CREATE INDEX idx_merkle_level ON merkle_nodes(level);
