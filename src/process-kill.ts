import { getProcessIdentities } from './process-identity.js';
import type { ActionResult } from './types.js';

export async function killProcess(pid: number, expectedToken: unknown, deps = {
  identities: getProcessIdentities,
  uid: () => process.getuid?.(),
  selfPid: process.pid,
  kill: (target: number): void => { process.kill(target, 'SIGTERM'); },
}): Promise<ActionResult> {
  if (!Number.isSafeInteger(pid) || pid <= 1 || pid === deps.selfPid) return { success: false, message: 'Invalid or protected PID' };
  if (typeof expectedToken !== 'string' || !/^[\da-f]{64}$/.test(expectedToken)) return { success: false, message: 'Process identity required; refresh the connection list' };
  const currentUid = deps.uid();
  if (currentUid === undefined) return { success: false, message: 'Cannot determine current user' };
  const identity = (await deps.identities(pid)).get(pid);
  if (!identity) return { success: false, message: 'Process identity unavailable; no signal sent' };
  if (identity.uid !== currentUid) return { success: false, message: 'Cannot kill process owned by another user' };
  if (identity.token !== expectedToken) return { success: false, message: 'Process identity changed; refresh before trying again' };
  // ps + kill is not an atomic kernel operation. This reduces stale-PID risk;
  // it cannot guarantee that the PID will not be reused between these calls.
  try { deps.kill(pid); return { success: true, message: `Sent SIGTERM to PID ${pid}` }; }
  catch { return { success: false, message: 'Could not signal the process; it may have already exited' }; }
}
