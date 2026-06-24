import type { ChildProcess } from 'node:child_process';

/**
 * End a child process's stdin safely. The stream can already be destroyed
 * (the child was SIGKILLed by a watchdog timeout, or sudo exited on a wrong
 * password mid-write), in which case `end()` emits an 'error' on the stdin
 * stream. Without a listener that error is unhandled and crashes the process.
 * A no-op 'error' listener absorbs it; close/exit still drive the caller's
 * resolve/reject.
 */
export function safeEndStdin(child: ChildProcess, data: string): void {
  if (!child.stdin) return;
  child.stdin.on('error', () => {});
  try {
    child.stdin.end(data);
  } catch {
    // stdin destroyed between the guard and the call — already handled above.
  }
}
