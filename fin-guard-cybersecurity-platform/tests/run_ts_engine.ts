/**
 * Cross-engine consistency runner — TypeScript side.
 *
 * Reads the shared fixture, runs each message through the TS analyzeMessage()
 * function, and writes a JSON results file that the Python comparison test
 * can consume.
 *
 * Usage:  npx tsx tests/run_ts_engine.ts
 */

import * as fs from 'fs'
import * as path from 'path'
import { analyzeMessage } from '../lib/analysis/engine'

interface Fixture {
  id: string
  category: string
  message: string
  expectRisk: string
  expectSignals: string[]
  expectAbsent?: string[]
}

interface TsResult {
  id: string
  riskLevel: string
  signalIds: string[]
  signalDetails: {
    id: string
    category: string
    severity: string
    title: string
    explanation: string
    evidence: string[]
  }[]
  summary: string
  nextSteps: string[]
  verification: string[]
}

const fixtureDir = path.resolve(__dirname, 'fixtures')
const fixtures: Fixture[] = JSON.parse(
  fs.readFileSync(path.join(fixtureDir, 'cross_engine_messages.json'), 'utf-8')
)

const results: TsResult[] = []

for (const f of fixtures) {
  const r = analyzeMessage(f.message)
  results.push({
    id: f.id,
    riskLevel: r.riskLevel,
    signalIds: r.signals.map((s) => s.id),
    signalDetails: r.signals.map((s) => ({
      id: s.id,
      category: s.category,
      severity: s.severity,
      title: s.title,
      explanation: s.explanation,
      evidence: s.evidence,
    })),
    summary: r.summary,
    nextSteps: r.nextSteps,
    verification: r.verification,
  })
}

const outPath = path.join(fixtureDir, 'ts_engine_results.json')
fs.writeFileSync(outPath, JSON.stringify(results, null, 2))
console.log(`Wrote ${results.length} results to ${outPath}`)
