import { Env } from "../types";
import { backfillConsistencyProofs } from "./backfill-consistency-proofs";
import { promoteEligibleCertificates } from "./ca-promotion";
import { runCheckpointMaintenance } from "./checkpoints";
import { runValidator } from "./validator";

export async function runCron(env: Env): Promise<void> {
  console.log("Executing cron tasks...");

  // If the consistency_proof table in transparency checkpoints database is empty, populate it.
  await backfillConsistencyProofs(env);

  // Promote eligble CAs as soon as they become eligible
  await promoteEligibleCertificates(env);

  // Create Checkpoints
  await runCheckpointMaintenance(env);

  // Run Validator
  await runValidator(env);

  console.log("Cron tasks finished...")

}