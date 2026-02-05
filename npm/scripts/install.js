#!/usr/bin/env node

/**
 * ZAP Schema Compiler (zapc) post-install script
 *
 * This script handles binary installation from optional platform-specific packages.
 * Falls back to downloading from GitHub releases if no package is available.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const https = require('https');

const PACKAGE_VERSION = require('../package.json').version;
const BIN_DIR = path.join(__dirname, '..', 'bin');
const BIN_NAME = process.platform === 'win32' ? 'zapc.exe' : 'zapc';
const BIN_PATH = path.join(BIN_DIR, BIN_NAME);

// Platform/arch to package name mapping
const PLATFORM_PACKAGES = {
  'darwin-arm64': '@zap-proto/zapc-darwin-arm64',
  'darwin-x64': '@zap-proto/zapc-darwin-x64',
  'linux-arm64': '@zap-proto/zapc-linux-arm64',
  'linux-x64': '@zap-proto/zapc-linux-x64',
  'win32-x64': '@zap-proto/zapc-win32-x64',
};

// GitHub release URL pattern
const GITHUB_RELEASE_URL = 'https://github.com/zap-proto/zap/releases/download';

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;
  return `${platform}-${arch}`;
}

function getBinaryFromOptionalPackage() {
  const platformKey = getPlatformKey();
  const packageName = PLATFORM_PACKAGES[platformKey];

  if (!packageName) {
    console.log(`No optional package for platform: ${platformKey}`);
    return null;
  }

  try {
    // Try to find the binary in the optional package
    const packagePath = require.resolve(`${packageName}/package.json`);
    const packageDir = path.dirname(packagePath);
    const binaryPath = path.join(packageDir, 'bin', BIN_NAME);

    if (fs.existsSync(binaryPath)) {
      return binaryPath;
    }
  } catch (e) {
    // Package not installed (optional dependency)
    console.log(`Optional package ${packageName} not installed`);
  }

  return null;
}

function downloadBinary() {
  return new Promise((resolve, reject) => {
    const platformKey = getPlatformKey();
    const ext = process.platform === 'win32' ? '.exe' : '';
    const archiveName = `zapc-${platformKey}${ext}`;
    const url = `${GITHUB_RELEASE_URL}/v${PACKAGE_VERSION}/${archiveName}`;

    console.log(`Downloading zapc from ${url}...`);

    const file = fs.createWriteStream(BIN_PATH);

    const request = https.get(url, (response) => {
      // Handle redirects
      if (response.statusCode === 302 || response.statusCode === 301) {
        https.get(response.headers.location, (redirectResponse) => {
          redirectResponse.pipe(file);
          file.on('finish', () => {
            file.close();
            fs.chmodSync(BIN_PATH, 0o755);
            resolve();
          });
        }).on('error', (err) => {
          fs.unlinkSync(BIN_PATH);
          reject(err);
        });
        return;
      }

      if (response.statusCode !== 200) {
        reject(new Error(`Download failed: ${response.statusCode}`));
        return;
      }

      response.pipe(file);
      file.on('finish', () => {
        file.close();
        fs.chmodSync(BIN_PATH, 0o755);
        resolve();
      });
    });

    request.on('error', (err) => {
      fs.unlinkSync(BIN_PATH);
      reject(err);
    });
  });
}

async function install() {
  // Ensure bin directory exists
  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }

  // First try optional platform-specific package
  const optionalBinary = getBinaryFromOptionalPackage();
  if (optionalBinary) {
    console.log(`Using binary from optional package: ${optionalBinary}`);

    // Create symlink or copy
    try {
      if (fs.existsSync(BIN_PATH)) {
        fs.unlinkSync(BIN_PATH);
      }

      // On Windows, copy; on Unix, symlink
      if (process.platform === 'win32') {
        fs.copyFileSync(optionalBinary, BIN_PATH);
      } else {
        fs.symlinkSync(optionalBinary, BIN_PATH);
      }

      console.log(`zapc installed successfully!`);
      return;
    } catch (e) {
      console.log(`Failed to link binary: ${e.message}`);
    }
  }

  // Fall back to downloading from GitHub releases
  try {
    await downloadBinary();
    console.log(`zapc downloaded and installed successfully!`);
  } catch (e) {
    console.error(`Failed to install zapc: ${e.message}`);
    console.error(`\nYou can try installing manually:`);
    console.error(`  1. Download the binary from https://github.com/zap-proto/zap/releases`);
    console.error(`  2. Place it in your PATH as 'zapc'`);
    console.error(`\nOr build from source:`);
    console.error(`  cargo install --path . --bin zapc`);
    process.exit(1);
  }
}

// Check if we're being called as a script (not required as a module)
if (require.main === module) {
  install().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { install };
