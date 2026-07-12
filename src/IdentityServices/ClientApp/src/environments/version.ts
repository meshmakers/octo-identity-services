const { version: packageVersion } = require('../../package.json');
const { resolve, relative } = require('path');
const { writeFileSync } = require('fs');

// OCTO_VERSION is injected by the MSBuild SPA targets (IdentityServices.csproj)
// from $(OctoVersion), which CI passes into the Docker build. Wildcard values
// like "0.1.*" are NuGet pin fallbacks, not real versions — ignore those and
// fall back to package.json (0.0.0) as before.
const envVersion = process.env.OCTO_VERSION;
const version = envVersion && !envVersion.includes('*') ? envVersion : packageVersion;

const versionInfo = { version };
const file = resolve(__dirname, 'currentVersion.ts');
writeFileSync(file, `// IMPORTANT: THIS FILE IS AUTO GENERATED! DO NOT MANUALLY EDIT OR CHECKIN!\nexport const VERSION = ${JSON.stringify(versionInfo, null, 4)};\n`, { encoding: 'utf-8' });
console.log(`Wrote version info ${versionInfo.version} to ${relative(resolve(__dirname, '..'), file)}`);
