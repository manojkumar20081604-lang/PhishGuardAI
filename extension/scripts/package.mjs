#!/usr/bin/env node
/**
 * Phase J packaging: zip the built extensions for store submission.
 *
 *   npm run package            -> both stores
 *   npm run package -- chrome  -> CWS only
 *   npm run package -- firefox -> AMO only
 *
 * Zips land in <repo>/store/packages/phishguard-ai-{chrome|firefox}-v<version>.zip
 * Sourcemaps and dotfiles are excluded; AMO reviewers get readable unminified code.
 */

import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const extRoot = resolve(here, '..');
const outDir = resolve(extRoot, '..', 'store', 'packages');

const version = JSON.parse(readFileSync(resolve(extRoot, 'manifest.json'), 'utf8')).version;
const targets = process.argv.slice(2);
const wanted = targets.length === 0 ? ['chrome', 'firefox'] : targets;

for (const browser of wanted) {
  const srcDir = resolve(extRoot, browser === 'chrome' ? 'dist' : 'dist-firefox');
  if (!existsSync(srcDir)) {
    console.error(`✗ ${srcDir} missing — run: npm run build:${browser}`);
    process.exitCode = 1;
    continue;
  }
  mkdirSync(outDir, { recursive: true });
  const out = resolve(outDir, `phishguard-ai-${browser}-v${version}.zip`);
  execSync(
    // -X: no extra file attrs · -x: exclude maps + dotfiles (zip runs inside srcDir)
    `zip -r -X -q "${out}" . -x "*.map" -x ".*" -x "__MACOSX*" -x "*/.DS_Store"`,
    { cwd: srcDir, stdio: 'inherit' }
  );
  const kb = (statSync(out).size / 1024).toFixed(0);
  console.log(`✓ ${browser} -> ${out} (${kb} KB)`);
}
