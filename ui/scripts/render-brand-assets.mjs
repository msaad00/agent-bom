// Render product copies from the canonical, code-native SVG mark.
// Run from the repository root: node ui/scripts/render-brand-assets.mjs
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import sharp from 'sharp';

const root = fileURLToPath(new URL('../../', import.meta.url));
const read = name => readFile(path.join(root, name));
const write = (name, data) => writeFile(path.join(root, name), data);
for (const theme of ['light', 'dark']) {
  await write(`ui/public/brand/mark-${theme}.svg`, await read(`docs/images/brand/mark-${theme}.svg`));
  await write(`docs/images/logo-${theme}.svg`, await read(`docs/images/brand/logo-${theme}.svg`));
}
const mark = await read('docs/images/brand/mark-dark.svg');
await write('site-docs/assets/brand/mark.svg', mark);
const mono = mark.toString().replace(/  <defs>[\s\S]*?<\/defs>\n/, '')
  .replaceAll('url(#abm)', '#ffffff').replaceAll('#34d399', '#ffffff')
  .replaceAll('#22d3ee', '#ffffff').replaceAll('#0c1210', 'none').replaceAll('#0f1a17', 'none');
await write('site-docs/assets/brand/mark-mono.svg', mono);
await write('docs/images/social-preview.png', await sharp(await read('docs/images/social-preview.svg')).png().toBuffer());
// ICO permits PNG payloads. Keep the existing 16px + 32px favicon sizes.
const sizes = [16, 32];
const icons = await Promise.all(sizes.map(size => sharp(mark).resize(size, size).png().toBuffer()));
const header = Buffer.alloc(6 + sizes.length * 16);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(sizes.length, 4);
let offset = header.length;
icons.forEach((icon, i) => {
  const entry = 6 + i * 16;
  header[entry] = sizes[i]; header[entry + 1] = sizes[i];
  header.writeUInt16LE(1, entry + 4); header.writeUInt16LE(32, entry + 6);
  header.writeUInt32LE(icon.length, entry + 8); header.writeUInt32LE(offset, entry + 12);
  offset += icon.length;
});
await write('ui/app/favicon.ico', Buffer.concat([header, ...icons]));
console.log('Rendered dashboard, docs, social preview, and favicon brand assets.');
