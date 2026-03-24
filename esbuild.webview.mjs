import * as esbuild from 'esbuild';

const isWatch = process.argv.includes('--watch');

/** @type {esbuild.BuildOptions} */
const config = {
  entryPoints: ['src/webview/threatModelApp.tsx'],
  bundle: true,
  outfile: 'media/webview/threatModelApp.js',
  format: 'iife',
  platform: 'browser',
  target: 'es2020',
  minify: !isWatch,
  sourcemap: isWatch,
  loader: {
    '.tsx': 'tsx',
    '.ts': 'ts',
    '.css': 'css',
  },
  define: {
    'process.env.NODE_ENV': isWatch ? '"development"' : '"production"',
  },
  // ReactFlow's CSS is imported as a side-effect
  // We inject it inline so the webview CSP doesn't need external CSS files
  jsx: 'automatic',
  jsxImportSource: 'react',
};

if (isWatch) {
  const ctx = await esbuild.context(config);
  await ctx.watch();
  console.log('Watching webview...');
} else {
  await esbuild.build(config);
  console.log('Webview built → media/webview/threatModelApp.js');
}
