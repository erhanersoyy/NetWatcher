import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export async function killProcess(pid: number): Promise<{ success: boolean; message: string }> {
  if (!Number.isInteger(pid) || pid <= 0) {
    return { success: false, message: 'Invalid PID' };
  }

  // Verify process exists and belongs to current user.
  // Compare numeric uid (not username) — macOS `ps -o user=` truncates long
  // names to 8 chars, which could cause false mismatches.
  const currentUid = process.getuid?.();
  if (currentUid === undefined) {
    return { success: false, message: 'Cannot determine current user' };
  }

  try {
    const { stdout } = await execFileAsync('ps', ['-p', String(pid), '-o', 'uid=']);
    const ownerUid = parseInt(stdout.trim(), 10);
    if (!Number.isInteger(ownerUid)) {
      return { success: false, message: 'Process not found' };
    }
    if (ownerUid !== currentUid) {
      return { success: false, message: 'Cannot kill process owned by another user' };
    }
  } catch {
    return { success: false, message: 'Process not found' };
  }

  try {
    process.kill(pid, 'SIGTERM');
    return { success: true, message: `Sent SIGTERM to PID ${pid}` };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to kill process';
    return { success: false, message };
  }
}
