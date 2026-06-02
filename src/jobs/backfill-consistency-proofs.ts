import { Env } from "../types";
import { generateConsistencyProof } from "../merkle";

export async function backfillConsistencyProofs(
  env: Env
): Promise<void> {

  const checkpoints = await env.DB.prepare(`
    SELECT id, tree_size
    FROM transparency_checkpoints
    ORDER BY id ASC
  `).all<{
    id: number;
    tree_size: number;
  }>();

  if (checkpoints.results.length < 2) {
    return;
  }

  const entries = await env.DB.prepare(`
    SELECT leaf_hash
    FROM verification_log
    WHERE leaf_hash IS NOT NULL
    ORDER BY tree_position ASC
  `).all<{ leaf_hash: string }>();

  const leafHashes = entries.results.map(e => e.leaf_hash);

  for (let i = 1; i < checkpoints.results.length; i++) {

    const current = checkpoints.results[i];
    const previous = checkpoints.results[i - 1];

    const existing = await env.DB.prepare(`
      SELECT consistency_proof
      FROM transparency_checkpoints
      WHERE id = ?
    `).bind(current.id).first<{ consistency_proof: string | null }>();

    if (existing?.consistency_proof) {
      continue;
    }

    const proof = await generateConsistencyProof(
      leafHashes,
      previous.tree_size,
      current.tree_size
    );

    await env.DB.prepare(`
      UPDATE transparency_checkpoints
      SET consistency_proof = ?
      WHERE id = ?
    `).bind(
      JSON.stringify({
        from_tree_size: previous.tree_size,
        to_tree_size: current.tree_size,
        proof
      }),
      current.id
    ).run();

    console.log(
      `Backfilled checkpoint ${current.id} (${previous.tree_size} -> ${current.tree_size})`
    );
  }
}