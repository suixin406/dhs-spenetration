import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const promptPath = path.join(root, 'PROMPT.md')
const patchPath = path.join(root, 'cordis.patch.yml')

function normalize(text) {
  return text.replace(/\r\n?/g, '\n')
}

function personaLines() {
  const lines = normalize(fs.readFileSync(promptPath, 'utf8')).split('\n')
  while (lines.length && (!lines[0].trim() || lines[0].trimStart().startsWith('#'))) lines.shift()
  while (lines.length && !lines.at(-1).trim()) lines.pop()
  return lines
}

const raw = normalize(fs.readFileSync(patchPath, 'utf8'))
const lines = raw.split('\n')
const start = lines.findIndex((line) => line.trim().startsWith('prefix:'))
if (start < 0) throw new Error('prefix: not found in cordis.patch.yml')

const indent = lines[start].length - lines[start].trimStart().length
let end = start + 1
if (['prefix: |', 'prefix: >', 'prefix: |-'].includes(lines[start].trim())) {
  while (end < lines.length) {
    const line = lines[end]
    if (!line.trim() || line.length - line.trimStart().length > indent) end += 1
    else break
  }
}

const prefix = ' '.repeat(indent)
const block = [prefix + 'prefix: |']
for (const line of personaLines()) block.push(line.trim() ? `${prefix}  ${line}` : '')
block.push('')
const output = [...lines.slice(0, start), ...block, ...lines.slice(end)].join('\n')
fs.writeFileSync(patchPath, output, 'utf8')
console.log(`synced PROMPT.md -> cordis.patch.yml (${Buffer.byteLength(output)} bytes)`)
