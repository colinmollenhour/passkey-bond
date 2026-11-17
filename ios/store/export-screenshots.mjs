// Copy the App Store screenshots out of an `xcresulttool export attachments`
// folder, named by their XCTAttachment names:
//   node ios/store/export-screenshots.mjs <attachments-dir> <out-dir> <prefix>
// writes <out-dir>/<prefix>-01-unlock.png and so on.
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const [source, out, prefix] = process.argv.slice(2);
if (!source || !out || !prefix) {
  throw new Error('Usage: export-screenshots.mjs <attachments-dir> <out-dir> <prefix>');
}

const manifest = JSON.parse(readFileSync(path.join(source, 'manifest.json'), 'utf8'));
mkdirSync(out, { recursive: true });
const written = [];
for (const test of manifest) {
  if (!String(test.testIdentifier ?? '').includes('StoreScreenshotTests')) continue;
  for (const attachment of test.attachments ?? []) {
    const exported = attachment.exportedFileName;
    const suggested = attachment.suggestedHumanReadableName ?? exported;
    // xcresulttool appends "_<index>_<UUID>" to the attachment name.
    const name = suggested.replace(/_\d+_[0-9A-F-]{36}(?=\.\w+$)/i, '');
    if (!/^\d\d-[\w-]+\.png$/.test(name)) continue;
    const target = path.join(out, `${prefix}-${name}`);
    copyFileSync(path.join(source, exported), target);
    written.push(target);
  }
}
if (written.length === 0) throw new Error(`No store screenshots found in ${source}`);
console.log(written.join('\n'));
