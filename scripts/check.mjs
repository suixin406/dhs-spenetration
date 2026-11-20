import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const errors = []
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8').replace(/\r\n?/g, '\n')
const dirs = (relative) => fs.readdirSync(path.join(root, relative), { withFileTypes: true })
  .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort()
const files = (relative, suffix = '') => fs.readdirSync(path.join(root, relative), { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(suffix)).map((entry) => entry.name).sort()

function fail(message) {
  errors.push(message)
}

const pkg = JSON.parse(read('package.json'))
const skillDirs = dirs('skills')
const knowledge = files('知识库', '.md').filter((name) => name !== 'README.md')
const cliTools = files('tools', '.py').filter((name) => !['scope_guard.py', 'sync-persona.py'].includes(name))
const actual = { skills: skillDirs.length, knowledgeArticles: knowledge.length, cliTools: cliTools.length }
for (const [key, value] of Object.entries(actual)) {
  if (pkg.projectStats?.[key] !== value) fail(`package.json projectStats.${key}=${pkg.projectStats?.[key]}, actual=${value}`)
}

for (const dir of skillDirs) {
  const relative = `skills/${dir}/SKILL.md`
  if (!fs.existsSync(path.join(root, relative))) {
    fail(`missing ${relative}`)
    continue
  }
  const text = read(relative)
  if (!text.startsWith('---\n')) fail(`${relative}: missing YAML frontmatter`)
  const name = text.match(/^name:\s*(.+)$/m)?.[1]?.trim()
  const description = text.match(/^description:\s*(.+)$/m)?.[1]?.trim()
  if (name !== dir) fail(`${relative}: name=${name}, expected ${dir}`)
  if (!description) fail(`${relative}: missing description`)
}

const promptLines = read('PROMPT.md').split('\n')
while (promptLines.length && (!promptLines[0].trim() || promptLines[0].trimStart().startsWith('#'))) promptLines.shift()
while (promptLines.length && !promptLines.at(-1).trim()) promptLines.pop()
const patchLines = read('cordis.patch.yml').split('\n')
const start = patchLines.findIndex((line) => line.trim() === 'prefix: |')
if (start < 0) fail('cordis.patch.yml: prefix block not found')
else {
  const indent = patchLines[start].length - patchLines[start].trimStart().length
  let end = start + 1
  while (end < patchLines.length) {
    const line = patchLines[end]
    if (!line.trim() || line.length - line.trimStart().length > indent) end += 1
    else break
  }
  const embedded = patchLines.slice(start + 1, end).map((line) => line ? line.slice(indent + 2) : '')
  while (embedded.length && !embedded.at(-1).trim()) embedded.pop()
  if (embedded.join('\n') !== promptLines.join('\n')) fail('PROMPT.md and cordis.patch.yml are out of sync; run npm run sync:persona')
}

for (const relative of ['README.md', '知识库/README.md', 'THIRD_PARTY_NOTICES.md']) {
  if (!fs.existsSync(path.join(root, relative))) continue
  const text = read(relative)
  const links = text.matchAll(/\[[^\]]*\]\((?!https?:|mailto:|#)([^)#]+)(?:#[^)]+)?\)/g)
  for (const match of links) {
    const target = decodeURIComponent(match[1])
    if (!fs.existsSync(path.resolve(path.dirname(path.join(root, relative)), target))) {
      fail(`${relative}: broken local link ${target}`)
    }
  }
}

const patchText = read('cordis.patch.yml')
if (/[A-Za-z]:[\\/](?:Users|Documents)[\\/]/.test(patchText)) fail('cordis.patch.yml contains a machine-specific absolute path')
if (!pkg.files?.includes('AUTHORIZED-TARGETS.template.json')) fail('authorization JSON template is not packaged')
if (!pkg.files?.includes('NOTICE') || !pkg.files?.includes('LICENSES')) fail('third-party license material is not packaged')

const scope = JSON.parse(read('AUTHORIZED-TARGETS.template.json'))
if (scope.version !== 1 || !Array.isArray(scope.targets) || !scope.targets.length) fail('invalid authorization template')

for (const relative of ['tools/apk_extract.py', 'tools/jsintel.py', 'tools/http_concurrent.py', 'tools/otp_brute.py']) {
  const text = read(relative)
  if (/verify\s*=\s*False/.test(text)) fail(`${relative}: TLS verification is disabled unconditionally`)
}

const readme = read('README.md')
for (const [value, label] of [[actual.skills, '技能'], [actual.knowledgeArticles, '知识正文'], [actual.cliTools, '命令行工具']]) {
  if (!readme.includes(`${value} 个${label}`) && !readme.includes(`${value} 篇${label}`)) fail(`README.md does not state current ${label} count (${value})`)
}

if (errors.length) {
  console.error(`check failed (${errors.length})`)
  for (const error of errors) console.error(`- ${error}`)
  process.exit(1)
}

console.log(`check passed: ${actual.skills} skills, ${actual.knowledgeArticles} knowledge articles, ${actual.cliTools} CLI tools`)
