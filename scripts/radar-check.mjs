// Compatibility entry point for the old Canvas check; current renderer uses MapLibre.
// Pure data regressions here; actual WebGL/CSP/interaction checks use ui-preview.mjs.
import { spawnSync } from 'node:child_process';
const result = spawnSync(process.execPath, ['--test', 'public/js/radar-data.test.js'], { stdio: 'inherit', cwd: new URL('../', import.meta.url) });
process.exitCode = result.status ?? 1;
