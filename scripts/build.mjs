/**
 * Production Build Script
 * Minifies HTML and removes console.log statements
 */

import { readFile, writeFile, mkdirSync, existsSync, copyFileSync, readdirSync, statSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { promisify } from 'util';

const readFileAsync = promisify(readFile);
const writeFileAsync = promisify(writeFile);

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Recursively copy directory
 */
function copyRecursive(src, dest) {
  const stat = statSync(src);
  if (stat.isDirectory()) {
    if (!existsSync(dest)) {
      mkdirSync(dest, { recursive: true });
    }
    const files = readdirSync(src);
    for (const file of files) {
      copyRecursive(join(src, file), join(dest, file));
    }
  } else {
    copyFileSync(src, dest);
  }
}

/**
 * Simple HTML minifier
 */
function minifyHTML(html) {
  return html
    // Remove comments
    .replace(/<!--[\s\S]*?-->/g, '')
    // Remove console.log statements
    .replace(/console\.(log|debug|info|warn|error)\([^)]*\);?\s*/g, '')
    // Remove extra whitespace
    .replace(/\s+/g, ' ')
    // Remove whitespace between tags
    .replace(/>\s+</g, '><')
    .trim();
}

/**
 * Build frontend assets
 */
async function build() {
  console.log('🔨 Building EmerCallPlus for production...');

  const sourcePath = join(__dirname, '..', 'index.html');
  const distPath = join(__dirname, '..', 'dist');

  // Create dist directory
  if (!existsSync(distPath)) {
    mkdirSync(distPath, { recursive: true });
  }

  // Read source
  console.log('📖 Reading index.html...');
  const source = await readFileAsync(sourcePath, 'utf-8');

  // Get original size
  const originalSize = Buffer.byteLength(source, 'utf-8');
  console.log(`📊 Original size: ${(originalSize / 1024).toFixed(2)} KB`);

  // Minify
  console.log('🗜️  Minifying...');
  const minified = minifyHTML(source);

  // Get new size
  const minifiedSize = Buffer.byteLength(minified, 'utf-8');
  console.log(`📊 Minified size: ${(minifiedSize / 1024).toFixed(2)} KB`);
  console.log(`📉 Reduced by: ${((1 - minifiedSize / originalSize) * 100).toFixed(1)}%`);

  // Write to dist
  const outputPath = join(distPath, 'index.html');
  await writeFileAsync(outputPath, minified, 'utf-8');
  console.log(`✅ Built: ${outputPath}`);

  // Copy lib directory recursively
  const libSource = join(__dirname, '..', 'lib');
  const libDist = join(distPath, 'lib');

  if (existsSync(libSource)) {
    copyRecursive(libSource, libDist);
    console.log(`📚 Copied lib/ to dist/`);
  }

  console.log('\n✨ Build complete!');
}

build().catch(console.error);
