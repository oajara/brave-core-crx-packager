/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Example usage:
// npm run package-tor-client -- --binary "/Applications/Google\\ Chrome\\ Canary.app/Contents/MacOS/Google\\ Chrome\\ Canary" --keys-directory path/to/key/dir

const commander = require('commander')
const crypto = require('crypto')
const execSync = require('child_process').execSync
const fs = require('fs')
const mkdirp = require('mkdirp')
const path = require('path')
const replace = require('replace-in-file')
const util = require('../lib/util')

// Downloads the current (platform-specific) Tor client from S3
const downloadTorClient = (platform) => {
  const torPath = path.join('build', 'tor-client-updater', 'downloads')
  const torS3Prefix = process.env.S3_DEMO_TOR_PREFIX

  const torVersion = '0.4.7.8'
  const braveVersion = '0'
  const exeSuffix = platform === 'win32' ? '.exe' : ''
  const torFilename = `tor-${torVersion}-${platform}-brave-${braveVersion}`
  const torURL = torS3Prefix + torFilename + exeSuffix

  let sha512Tor = ''

  switch (platform) {
    case 'darwin':
      sha512Tor = '068f240ee81a658880d345d4a18261901e39ad273433d8359abbd0060b6926d171e4c0aa773754927dc7a714533decdd06cb5a233b87d30e871fcd2064f07058'
      break
    case 'linux':
      sha512Tor = '5e1f79ffbd6bd83bdcbaf1762d902241b62090a3c4cc04042c6d3e252f424f97b8d6932a3aaa675ba65813d485c6a1e55aeb6c250d0937cee26d4d4118150571'
      break
    case 'win32':
      sha512Tor = '66b97de8edbc7626bf05c7d0bdab04f4664f5219c85a90cc49825ffb5355fe32ebac3cb82c39db92d169812842c0c4440d1050042847926abdbbd729a681f55f'
      break
    default:
      throw new Error('Tor client download failed; unrecognized platform: ' + platform)
  }

  mkdirp.sync(torPath)

  const torClient = path.join(torPath, torFilename)
  const cmd = 'aws s3 cp ' + torURL + ' ' + torClient

  // Download the client
  execSync(cmd)

  // Verify the checksum
  if (!verifyChecksum(torClient, sha512Tor)) {
    console.error(`Tor client checksum verification failed on ${platform}`)
    process.exit(1)
  }

  // Make it executable
  fs.chmodSync(torClient, 0o755)

  return torClient
}

const getOriginalManifest = (platform) => {
  return path.join('manifests', 'tor-client-updater', `tor-client-updater-${platform}-manifest.json`)
}

const packageTorClient = (binary, endpoint, region, platform, key,
  publisherProofKey) => {
  const originalManifest = getOriginalManifest(platform)
  const parsedManifest = util.parseManifest(originalManifest)
  const id = util.getIDFromBase64PublicKey(parsedManifest.key)

  util.getNextVersion(endpoint, region, id).then((version) => {
    const stagingDir = path.join('build', 'tor-client-updater', platform)
    const torClient = downloadTorClient(platform)
    const crxOutputDir = path.join('build', 'tor-client-updater')
    const crxFile = path.join(crxOutputDir, `tor-client-updater-${platform}.crx`)
    const privateKeyFile = !fs.lstatSync(key).isDirectory() ? key : path.join(key, `tor-client-updater-${platform}.pem`)
    stageFiles(platform, torClient, version, stagingDir)
    util.generateCRXFile(binary, crxFile, privateKeyFile, publisherProofKey,
      stagingDir)
    console.log(`Generated ${crxFile} with version number ${version}`)
  })
}

const stageFiles = (platform, torClient, version, outputDir) => {
  const originalManifest = getOriginalManifest(platform)
  const outputManifest = path.join(outputDir, 'manifest.json')
  const outputTorClient = path.join(outputDir, path.parse(torClient).base)
  const outputTorrc = path.join(outputDir, 'tor-torrc')
  const inputTorrc = path.join('resources', 'tor', 'torrc')

  const replaceOptions = {
    files: outputManifest,
    from: /0\.0\.0/,
    to: version
  }

  mkdirp.sync(outputDir)

  fs.copyFileSync(originalManifest, outputManifest)
  fs.copyFileSync(torClient, outputTorClient)
  fs.copyFileSync(inputTorrc, outputTorrc)

  replace.sync(replaceOptions)
}

// Does a hash comparison on a file against a given hash
const verifyChecksum = (file, hash) => {
  const filecontent = fs.readFileSync(file)
  const computedHash = crypto.createHash('sha512').update(filecontent).digest('hex')
  console.log(`${file} has hash ${computedHash}`)
  return hash === computedHash
}

util.installErrorHandlers()

util.addCommonScriptOptions(
  commander
    .option('-d, --keys-directory <dir>', 'directory containing private keys for signing crx files', 'abc')
    .option('-f, --key-file <file>', 'private key file for signing crx', 'key.pem'))
  .parse(process.argv)

let keyParam = ''

if (fs.existsSync(commander.keyFile)) {
  keyParam = commander.keyFile
} else if (fs.existsSync(commander.keysDirectory)) {
  keyParam = commander.keysDirectory
} else {
  throw new Error('Missing or invalid private key file/directory')
}

util.createTableIfNotExists(commander.endpoint, commander.region).then(() => {
  packageTorClient(commander.binary, commander.endpoint, commander.region,
    'darwin', keyParam, commander.publisherProofKey)
  packageTorClient(commander.binary, commander.endpoint, commander.region,
    'linux', keyParam, commander.publisherProofKey)
  packageTorClient(commander.binary, commander.endpoint, commander.region,
    'win32', keyParam, commander.publisherProofKey)
})
