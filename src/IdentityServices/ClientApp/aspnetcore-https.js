// This script sets up HTTPS for the application using the ASP.NET Core HTTPS certificate
const fs = require('fs');
const spawn = require('child_process').spawn;
const path = require('path');

const baseFolder =
  process.env.APPDATA !== undefined && process.env.APPDATA !== ''
    ? `${process.env.APPDATA}/ASP.NET/https`
    : `${process.env.HOME}/.aspnet/https`;

// Use shared 'client-app' certificate for all Angular dev servers
const certificateName = 'client-app';

const certFilePath = path.join(baseFolder, `${certificateName}.pem`);
const keyFilePath = path.join(baseFolder, `${certificateName}.key`);

// Local symlinks for Angular dev server (matching Refinery Studio pattern)
const localCertPath = path.join(__dirname, 'localhost.crt');
const localKeyPath = path.join(__dirname, 'localhost.key');

function createSymlinks() {
  // Remove old symlinks if they exist
  try {
    if (fs.existsSync(localCertPath)) fs.unlinkSync(localCertPath);
    if (fs.existsSync(localKeyPath)) fs.unlinkSync(localKeyPath);
  } catch (e) {
    // Ignore errors
  }

  // Create symlinks
  fs.symlinkSync(certFilePath, localCertPath);
  fs.symlinkSync(keyFilePath, localKeyPath);
  console.log(`Created symlinks to SSL certificates: ${certFilePath}`);
}

if (!fs.existsSync(certFilePath) || !fs.existsSync(keyFilePath)) {
  console.log('Generating SSL certificate...');
  spawn('dotnet', [
    'dev-certs',
    'https',
    '--export-path',
    certFilePath,
    '--format',
    'Pem',
    '--no-password',
  ], {stdio: 'inherit'})
    .on('exit', (code) => {
      if (code === 0) {
        createSymlinks();
      }
      process.exit(code);
    });
} else {
  createSymlinks();
}
