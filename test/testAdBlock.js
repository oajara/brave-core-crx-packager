import assert from 'node:assert/strict'
import test from 'node:test'
import tmp from 'tmp'
import fs from 'fs'
import { spawnSync } from 'child_process'

import { generateResourcesFile, sanityCheckList } from '../lib/adBlockRustUtils.js'

test('generateResourcesFile', async (t) => {
  const tmpfile = tmp.fileSync({ discardDescriptor: true })
  return generateResourcesFile(tmpfile.name).then(() => {
    const filedata = fs.readFileSync(tmpfile.name)
    const resources = JSON.parse(filedata)
    assert.ok(Object.prototype.toString.call(resources) === '[object Array]')
    assert.ok(resources.length >= 10)
    for (const r of resources) {
      assert.ok(r.kind !== undefined)
      assert.ok(r.kind.mime !== undefined)
      if (r.kind.mime === 'application/javascript' || r.kind.mime === 'fn/javascript') {
        const script = atob(r.content)
        const subprocess = spawnSync('node', ['--check'], { input: script })
        assert.ok(subprocess.status === 0, 'Resource ' + r.name + ' is not valid JS:\n' + subprocess.stderr.toString() + '\n' + script)
      }
    }
  })
})

test('sanityCheckList', async (t) => {
  // Verify that https://bravesoftware.slack.com/archives/C2FQMN4AD/p1704501704164999 would have been caught
  const corruptedList = fs.readFileSync('./test/elc-1.0.3814-corrupted.txt', { encoding: 'utf8' })
  let failureMessage
  try {
    sanityCheckList({ title: 'corrupted list', data: corruptedList, format: 'Standard' })
  } catch (error) {
    failureMessage = error.message
  }
  assert.ok(failureMessage.startsWith('corrupted list failed sanity check for'))
})
