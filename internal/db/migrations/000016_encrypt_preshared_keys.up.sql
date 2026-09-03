ALTER TABLE peers
    ADD COLUMN preshared_key_ciphertext BYTEA,
    ADD COLUMN preshared_key_version SMALLINT,
    ADD CONSTRAINT chk_peers_preshared_key_encryption CHECK (
        (preshared_key_ciphertext IS NULL AND preshared_key_version IS NULL)
        OR (
            preshared_key_ciphertext IS NOT NULL
            AND preshared_key_version = 1
            AND octet_length(preshared_key_ciphertext) >= 40
        )
    ),
    ADD CONSTRAINT chk_peers_preshared_key_single_representation CHECK (
        preshared_key = '' OR preshared_key_ciphertext IS NULL
    );

ALTER TABLE peer_operations
    ADD COLUMN preshared_key_ciphertext BYTEA,
    ADD COLUMN preshared_key_version SMALLINT,
    ADD CONSTRAINT chk_peer_operations_preshared_key_encryption CHECK (
        (preshared_key_ciphertext IS NULL AND preshared_key_version IS NULL)
        OR (
            preshared_key_ciphertext IS NOT NULL
            AND preshared_key_version = 1
            AND octet_length(preshared_key_ciphertext) >= 40
        )
    ),
    ADD CONSTRAINT chk_peer_operations_preshared_key_single_representation CHECK (
        preshared_key = '' OR preshared_key_ciphertext IS NULL
    );

COMMENT ON COLUMN peers.preshared_key IS
    'Legacy dual-read source only; new writes must use preshared_key_ciphertext';
COMMENT ON COLUMN peer_operations.preshared_key IS
    'Legacy dual-read source only; new writes must use preshared_key_ciphertext';

ALTER TABLE mesh_members
    ADD COLUMN preshared_key_ciphertext BYTEA,
    ADD COLUMN preshared_key_version SMALLINT,
    ADD CONSTRAINT chk_mesh_members_preshared_key_encryption CHECK (
        (preshared_key_ciphertext IS NULL AND preshared_key_version IS NULL)
        OR (
            preshared_key_ciphertext IS NOT NULL
            AND preshared_key_version = 1
            AND octet_length(preshared_key_ciphertext) >= 40
        )
    ),
    ADD CONSTRAINT chk_mesh_members_preshared_key_single_representation CHECK (
        preshared_key = '' OR preshared_key_ciphertext IS NULL
    );

COMMENT ON COLUMN mesh_members.preshared_key IS
    'Legacy backfill source only; application code does not consume this value';
