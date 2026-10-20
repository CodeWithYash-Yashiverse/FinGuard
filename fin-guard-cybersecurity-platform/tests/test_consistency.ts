/**
 * Phase 5.5 — TypeScript consistency and fixture regression tests.
 *
 * Verifies that the TypeScript detection engine meets all fixture expectations
 * in tests/fixtures/cross_engine_messages.json.
 *
 * Run with:  npx tsx tests/test_consistency.ts
 */

import * as fs from 'fs'
import * as path from 'path'
import { analyzeMessage, ENGINE_NAME, ENGINE_VERSION } from '../lib/analysis/engine'
import type { RiskLevel } from '../lib/analysis/types'

interface Fixture {
  id: string
  category: string
  message: string
  expectRisk: RiskLevel
  expectSignals: string[]
  expectAbsent?: string[]
}

const fixtureDir = path.resolve(__dirname, 'fixtures')
const fixtures: Fixture[] = JSON.parse(
  fs.readFileSync(path.join(fixtureDir, 'cross_engine_messages.json'), 'utf-8')
)

const snapshotPath = path.join(fixtureDir, 'ts_engine_results.json')
const snapshot: Record<string, any> = fs.existsSync(snapshotPath)
  ? Object.fromEntries(
      JSON.parse(fs.readFileSync(snapshotPath, 'utf-8')).map((r: any) => [r.id, r])
    )
  : {}

console.log(`Running TypeScript engine consistency tests on ${fixtures.length} fixtures...\n`)

let passed = 0
let failed = 0
const errors: string[] = []

for (const fixture of fixtures) {
  const result = analyzeMessage(fixture.message)
  const signalIds = result.signals.map((s) => s.id)
  const signalIdSet = new Set(signalIds)

  // 1. Verify expected signals are detected
  const missingSignals = fixture.expectSignals.filter((id) => !signalIdSet.has(id))
  if (missingSignals.length > 0) {
    errors.push(
      `[${fixture.id}] Missing expected signal(s): ${missingSignals.join(', ')} (found: ${signalIds.join(', ') || 'none'})`
    )
    failed++
    continue
  }

  // 2. Verify absent signals are not detected
  const unexpectedSignals = (fixture.expectAbsent ?? []).filter((id) => signalIdSet.has(id))
  if (unexpectedSignals.length > 0) {
    errors.push(
      `[${fixture.id}] Unexpected signal(s) present: ${unexpectedSignals.join(', ')}`
    )
    failed++
    continue
  }

  // 3. Verify against snapshot if present (ensures deterministic regression tracking)
  if (snapshot[fixture.id]) {
    const snap = snapshot[fixture.id]
    if (result.riskLevel !== snap.riskLevel) {
      errors.push(
        `[${fixture.id}] Snapshot riskLevel drift: expected '${snap.riskLevel}', got '${result.riskLevel}'`
      )
      failed++
      continue
    }
    const snapSignalIds = sorted(snap.signalIds)
    const currentSignalIds = sorted(signalIds)
    if (JSON.stringify(snapSignalIds) !== JSON.stringify(currentSignalIds)) {
      errors.push(
        `[${fixture.id}] Snapshot signal IDs drift: expected ${JSON.stringify(snapSignalIds)}, got ${JSON.stringify(currentSignalIds)}`
      )
      failed++
      continue
    }

    // Verify evidence snippets match snapshot (ensures redaction regressions are caught)
    const snapEvidence = snap.signalDetails.flatMap((s: any) => s.evidence)
    const currentEvidence = result.signals.flatMap((s) => s.evidence)
    if (JSON.stringify(snapEvidence) !== JSON.stringify(currentEvidence)) {
      errors.push(
        `[${fixture.id}] Snapshot evidence drift: expected ${JSON.stringify(snapEvidence)}, got ${JSON.stringify(currentEvidence)}`
      )
      failed++
      continue
    }
  }

  // 4. Verify engine metadata
  if (result.engine.name !== ENGINE_NAME || result.engine.version !== ENGINE_VERSION) {
    errors.push(
      `[${fixture.id}] Invalid engine metadata: ${JSON.stringify(result.engine)}`
    )
    failed++
    continue
  }

  // 5. Verify basic structural invariants
  if (!result.summary || typeof result.summary !== 'string') {
    errors.push(`[${fixture.id}] Missing or empty summary`)
    failed++
    continue
  }

  if (!Array.isArray(result.nextSteps) || result.nextSteps.length === 0) {
    errors.push(`[${fixture.id}] Missing nextSteps`)
    failed++
    continue
  }

  if (!Array.isArray(result.verification) || result.verification.length === 0) {
    errors.push(`[${fixture.id}] Missing verification guidance`)
    failed++
    continue
  }

  passed++
}

function sorted(arr: string[]): string[] {
  return [...arr].sort()
}

console.log(`Results: ${passed} passed, ${failed} failed out of ${fixtures.length} tests.`)

if (failed > 0) {
  console.error('\nFailures:')
  for (const err of errors) {
    console.error(`  - ${err}`)
  }
  process.exit(1)
} else {
  console.log('All TypeScript engine consistency tests passed successfully.')
}
