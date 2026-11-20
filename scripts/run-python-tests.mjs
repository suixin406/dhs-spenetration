import { spawnSync } from 'node:child_process'

const candidates = []
if (process.env.PYTHON) candidates.push([process.env.PYTHON, []])
if (process.platform === 'win32') candidates.push(['py', ['-3']], ['python', []], ['python3', []])
else candidates.push(['python3', []], ['python', []])

for (const [command, prefix] of candidates) {
  const probe = spawnSync(command, [...prefix, '--version'], { encoding: 'utf8' })
  if (probe.error || probe.status !== 0) continue
  console.log((probe.stdout || probe.stderr).trim())
  const result = spawnSync(
    command,
    [...prefix, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
    { stdio: 'inherit' },
  )
  process.exit(result.status ?? 1)
}

console.error('Python 3.10+ not found. Set the PYTHON environment variable to an interpreter path.')
process.exit(1)
