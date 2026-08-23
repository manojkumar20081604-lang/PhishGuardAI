import { defineConfig, type Plugin } from 'vite';
import { viteStaticCopy } from 'vite-plugin-static-copy';
import path from 'path';
import { existsSync, rmSync, readFileSync, writeFileSync } from 'fs';

const __dirname = import.meta.dirname;

/**
 * ORT's bundler emits a default-fallback copy of the wasm binary next to the
 * chunk. The engine ALWAYS sets env.wasm.wasmPaths -> vendor/ort/ before
 * session creation, so this root copy is provably dead weight (~13MB).
 */
function pruneOrtDuplicateWasm(): Plugin {
  let outDir = '';
  return {
    name: 'prune-ort-duplicate-wasm',
    apply: 'build',
    configResolved(config) {
      outDir = path.resolve(__dirname, config.build.outDir);
    },
    closeBundle() {
      const dupe = path.join(outDir, 'ort-wasm-simd-threaded.wasm');
      const keptCopy = path.join(outDir, 'vendor', 'ort', 'ort-wasm-simd-threaded.wasm');
      if (existsSync(dupe) && existsSync(keptCopy)) {
        rmSync(dupe);
        console.log(`[prune] removed dead ORT wasm duplicate (${dupe})`);
      }
    },
  };
}

/**
 * Emits the manifest from ONE template with browser-specific patches:
 *  - firefox: event-page fallback scripts + gecko identity (MV3 differences)
 *  - chrome:  template as-is
 */
function emitManifest(browser: 'chrome' | 'firefox'): Plugin {
  let outDir = '';
  return {
    name: `emit-manifest-${browser}`,
    apply: 'build',
    configResolved(config) {
      outDir = path.resolve(__dirname, config.build.outDir);
    },
    closeBundle() {
      const manifest = JSON.parse(
        readFileSync(path.resolve(__dirname, 'manifest.json'), 'utf-8')
      );

      if (browser === 'firefox') {
        manifest.background = {
          service_worker: 'background.js',
          scripts: ['background.js'], // event page fallback (Firefox ignores SW key)
          type: 'module',
        };
        manifest.browser_specific_settings = {
          gecko: {
            id: 'phishguard@example.com', // TODO: real ID before AMO submission
            // 140 = first version supporting data_collection_permissions;
            // also matches current Firefox ESR baseline (nothing pre-140 is used)
            strict_min_version: '140.0',
            // AMO data-practices declaration: PhishGuard collects nothing -
            // all analysis is local (clears MISSING_DATA_COLLECTION_PERMISSIONS)
            data_collection_permissions: {
              required: ['none'],
            },
          },
        };
      }

      writeFileSync(
        path.join(outDir, 'manifest.json'),
        JSON.stringify(manifest, null, 2)
      );
      console.log(`[manifest] wrote ${browser} variant -> ${outDir}/manifest.json`);
    },
  };
}

export default defineConfig(({ mode }) => {
  const isFirefox = mode === 'firefox';
  
  return {
    root: '.',
    publicDir: 'public',
    build: {
      outDir: isFirefox ? 'dist-firefox' : 'dist',
      emptyOutDir: true,
      minify: mode === 'production' ? 'esbuild' : false,
      sourcemap: mode !== 'production',
      rollupOptions: {
        input: {
          popup: 'src/popup/popup.html',
          background: 'src/background/index.ts',
          content: 'src/content/index.ts',
          options: 'src/options/options.html',
        },
        output: {
          entryFileNames: '[name].js',
          chunkFileNames: '[name].js',
          assetFileNames: '[name].[ext]',
        },
      },
    },
    plugins: [
      pruneOrtDuplicateWasm(),
      emitManifest(isFirefox ? 'firefox' : 'chrome'),
      viteStaticCopy({
        targets: [
          { src: 'icons', dest: '.' },
        ],
      }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
        '@analyzer': path.resolve(__dirname, 'src/analyzer'),
        '@utils': path.resolve(__dirname, 'src/utils'),
      },
    },
  };
});