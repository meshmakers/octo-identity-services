const { version } = require('../../package.json');
const { resolve, relative } = require('path');
const { writeFileSync } = require('fs');

const versionInfo = { version };
const file = resolve(__dirname, 'currentVersion.ts');
writeFileSync(file, `// IMPORTANT: THIS FILE IS AUTO GENERATED! DO NOT MANUALLY EDIT OR CHECKIN!\nexport const VERSION = ${JSON.stringify(versionInfo, null, 4)};\n`, { encoding: 'utf-8' });
console.log(`Wrote version info ${versionInfo.version} to ${relative(resolve(__dirname, '..'), file)}`);
