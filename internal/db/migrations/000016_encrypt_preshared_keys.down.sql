DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM peers WHERE preshared_key_ciphertext IS NOT NULL)
       OR EXISTS (SELECT 1 FROM peer_operations WHERE preshared_key_ciphertext IS NOT NULL)
       OR EXISTS (SELECT 1 FROM mesh_members WHERE preshared_key_ciphertext IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back encrypted PSK columns while ciphertext exists';
    END IF;
END
$$;

ALTER TABLE mesh_members
    DROP CONSTRAINT chk_mesh_members_preshared_key_single_representation,
    DROP CONSTRAINT chk_mesh_members_preshared_key_encryption,
    DROP COLUMN preshared_key_version,
    DROP COLUMN preshared_key_ciphertext;

ALTER TABLE peer_operations
    DROP CONSTRAINT chk_peer_operations_preshared_key_single_representation,
    DROP CONSTRAINT chk_peer_operations_preshared_key_encryption,
    DROP COLUMN preshared_key_version,
    DROP COLUMN preshared_key_ciphertext;

ALTER TABLE peers
    DROP CONSTRAINT chk_peers_preshared_key_single_representation,
    DROP CONSTRAINT chk_peers_preshared_key_encryption,
    DROP COLUMN preshared_key_version,
    DROP COLUMN preshared_key_ciphertext;
