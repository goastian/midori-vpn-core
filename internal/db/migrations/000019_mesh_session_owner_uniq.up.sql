-- Deduplicate existing session meshes per owner: keep the most recently
-- updated row, delete the rest along with their members. This must run
-- before the unique index below can be created without conflicts.
WITH ranked AS (
    SELECT id,
           owner_id,
           ROW_NUMBER() OVER (
               PARTITION BY owner_id
               ORDER BY updated_at DESC, created_at DESC, id
           ) AS rn
    FROM mesh_networks
    WHERE is_session = TRUE
),
to_delete AS (
    SELECT id FROM ranked WHERE rn > 1
)
DELETE FROM mesh_networks WHERE id IN (SELECT id FROM to_delete);

-- Enforce: at most one session mesh per owner. Auto-provisioned session
-- meshes must be idempotent; manual meshes (is_session=FALSE) are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS mesh_networks_session_owner_uniq
    ON mesh_networks (owner_id)
    WHERE is_session = TRUE;
