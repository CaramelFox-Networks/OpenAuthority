import { Env } from "../types";
import { shouldCreateCheckpoint, createCheckpoint } from "../merkle";

export async function runCheckpointMaintenance(
  env: Env
): Promise<void> {

  if (await shouldCreateCheckpoint(env)) {
    console.log("Creating scheduled checkpoint...");
    await createCheckpoint(env);
  }

}