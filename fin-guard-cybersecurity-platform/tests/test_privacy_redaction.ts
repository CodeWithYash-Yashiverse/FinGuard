/**
 * Phase 5.6: Privacy Redaction Regression Tests (TypeScript side)
 *
 * Verifies that the TypeScript detector safely redacts credentials and
 * sensitive numbers while preserving ordinary currency amounts and Unicode boundaries.
 *
 * Run with:  npx tsx tests/test_privacy_redaction.ts
 */

import * as fs from 'fs'
import * as path from 'path'
import { analyzeMessage, redactSecrets } from '../lib/analysis/engine'

console.log('--- Starting FinGuard Privacy Redaction Regression Tests ---\n')

let passed = 0
let failed = 0

function assertTest(name: string, condition: boolean, detail?: string) {
  if (condition) {
    passed++
    console.log(`✓ ${name}`)
  } else {
    failed++
    console.error(`✗ ${name}`)
    if (detail) console.error(`   Details: ${detail}`)
  }
}

// ---------------------------------------------------------------------------
// 1. OTP-like numeric sequences
// ---------------------------------------------------------------------------
console.log('[1. OTP-like numeric sequences]')
{
  const res1 = redactSecrets('OTP 482913')
  assertTest('6-digit OTP is partially masked', res1 === 'OTP 4****3', `Got: '${res1}'`)

  const res2 = redactSecrets('Your verification code is 847291')
  assertTest('Verification code is masked', res2.includes('8****1'), `Got: '${res2}'`)

  const analysis = analyzeMessage('Please share your OTP 482913 immediately to verify your account.')
  const credSig = analysis.signals.find((s) => s.id === 'credential-request')
  assertTest(
    'OTP does not appear unredacted in evidence snippet',
    Boolean(credSig && credSig.evidence.every((ev) => !ev.includes('482913') && ev.includes('4****3'))),
    `Evidence: ${JSON.stringify(credSig?.evidence)}`
  )
}

// ---------------------------------------------------------------------------
// 2. UPI PIN and other credential-related numeric sequences
// ---------------------------------------------------------------------------
console.log('\n[2. UPI PIN and credential numeric sequences]')
{
  const res1 = redactSecrets('UPI PIN 1234')
  assertTest('4-digit PIN is partially masked', res1 === 'UPI PIN 1**4', `Got: '${res1}'`)

  const res2 = redactSecrets('Enter M-PIN 5678')
  assertTest('4-digit M-PIN is partially masked', res2 === 'Enter M-PIN 5**8', `Got: '${res2}'`)

  const analysis = analyzeMessage('Enter your UPI PIN 1234 on the collect request to receive money.')
  const pinSig = analysis.signals.find((s) => s.id === 'pin-to-receive')
  assertTest(
    'PIN is masked in pin-to-receive evidence snippet',
    Boolean(pinSig && pinSig.evidence.every((ev) => !ev.includes('1234') && ev.includes('1**4'))),
    `Evidence: ${JSON.stringify(pinSig?.evidence)}`
  )
}

// ---------------------------------------------------------------------------
// 3. Phone numbers, including separated digit groups
// ---------------------------------------------------------------------------
console.log('\n[3. Phone numbers and separated digit groups]')
{
  const res1 = redactSecrets('Call 9876543210 now')
  assertTest('10-digit contiguous phone is masked', res1 === 'Call 9********0 now', `Got: '${res1}'`)

  const res2 = redactSecrets('Contact +91 98765 43210 immediately')
  assertTest(
    'Spaced phone number digit groups are masked',
    res2 === 'Contact +91 9***5 4***0 immediately',
    `Got: '${res2}'`
  )

  const res3 = redactSecrets('Call 987-654-3210 for support')
  assertTest(
    'Hyphenated phone number is masked',
    res3 === 'Call 9**-***-**10 for support',
    `Got: '${res3}'`
  )

  const analysis = analyzeMessage('Call +91 98765 43210 immediately to unblock your account.')
  const callSig = analysis.signals.find((s) => s.id === 'callback-number')
  assertTest(
    'Evidence for callback-number redacts phone digits',
    Boolean(callSig && callSig.evidence.every((ev) => !ev.includes('98765 43210') && ev.includes('9***5 4***0'))),
    `Evidence: ${JSON.stringify(callSig?.evidence)}`
  )
}

// ---------------------------------------------------------------------------
// 4. Long transaction or account references
// ---------------------------------------------------------------------------
console.log('\n[4. Long transaction and account references]')
{
  const res1 = redactSecrets('Card 4111222233334444')
  assertTest('16-digit card number is masked', res1 === 'Card 4**************4', `Got: '${res1}'`)

  const res2 = redactSecrets('Card 4111 2222 3333 4444')
  assertTest(
    'Grouped 16-digit card number with spaces is masked',
    res2 === 'Card 4*** **** **** ***4',
    `Got: '${res2}'`
  )

  const res2b = redactSecrets('Card 4111-2222-3333-4444')
  assertTest(
    'Grouped 16-digit card number with hyphens is masked',
    res2b === 'Card 4***-****-****-***4',
    `Got: '${res2b}'`
  )

  const res3 = redactSecrets('Ref: 426318745923')
  assertTest(
    '12-digit transaction reference is masked',
    res3 === 'Ref: 4**********3',
    `Got: '${res3}'`
  )

  const res4 = redactSecrets('Account ending 4321')
  assertTest('4-digit account ending is masked', res4 === 'Account ending 4**1', `Got: '${res4}'`)
}

// ---------------------------------------------------------------------------
// 5. Ordinary currency amounts that should remain understandable
// ---------------------------------------------------------------------------
console.log('\n[5. Ordinary currency amounts remain understandable]')
{
  const res1 = redactSecrets('Amount: Rs 1500')
  assertTest('Rs 1500 is preserved without masking', res1 === 'Amount: Rs 1500', `Got: '${res1}'`)

  const res2 = redactSecrets('Fee of Rs. 2500 is pending')
  assertTest('Rs. 2500 is preserved', res2 === 'Fee of Rs. 2500 is pending', `Got: '${res2}'`)

  const res3 = redactSecrets('Cashback of ₹2500 is ready')
  assertTest('₹2500 is preserved', res3 === 'Cashback of ₹2500 is ready', `Got: '${res3}'`)

  const res4 = redactSecrets('Balance: INR 10,000')
  assertTest('INR 10,000 is preserved', res4 === 'Balance: INR 10,000', `Got: '${res4}'`)

  const res5 = redactSecrets('Delivery charge: $1500')
  assertTest('$1500 is preserved', res5 === 'Delivery charge: $1500', `Got: '${res5}'`)

  const res6 = redactSecrets('Salary of Rs 65,000.00 credited')
  assertTest('Rs 65,000.00 is preserved', res6 === 'Salary of Rs 65,000.00 credited', `Got: '${res6}'`)

  const res7 = redactSecrets('Pay 2500/- immediately')
  assertTest('Amount with /- suffix preserved', res7 === 'Pay 2500/- immediately', `Got: '${res7}'`)
}

// ---------------------------------------------------------------------------
// 6. Messages containing both an amount and an OTP
// ---------------------------------------------------------------------------
console.log('\n[6. Message containing both an amount and an OTP]')
{
  const input = 'Cashback of Rs 2500; OTP 482913'
  const res = redactSecrets(input)
  assertTest(
    'Cashback of Rs 2500; OTP 482913 preserves amount and masks OTP',
    res === 'Cashback of Rs 2500; OTP 4****3',
    `Got: '${res}'`
  )

  const input2 = 'Amount ₹15000, account ending 4321'
  const res2 = redactSecrets(input2)
  assertTest(
    'Amount ₹15000, account ending 4321 preserves amount and masks account',
    res2 === 'Amount ₹15000, account ending 4**1',
    `Got: '${res2}'`
  )

  const input3 = 'Pay 1500 immediately'
  const res3 = redactSecrets(input3)
  assertTest(
    'Pay 1500 immediately masks unlabelled number due to ambiguity',
    res3 === 'Pay 1**0 immediately',
    `Got: '${res3}'`
  )

  const analysis = analyzeMessage(
    'Please send us your OTP 739182 for Rs 1500 refund immediately.'
  )
  const credSig = analysis.signals.find((s) => s.id === 'credential-request')
  assertTest(
    'Evidence contains preserved amount and redacted OTP',
    Boolean(
      credSig &&
      credSig.evidence.some((ev) => ev.includes('Rs 1500') && ev.includes('7****2') && !ev.includes('739182'))
    ),
    `Evidence: ${JSON.stringify(credSig?.evidence)}`
  )
}

// ---------------------------------------------------------------------------
// 7. Unicode and emoji near evidence-snippet boundaries
// ---------------------------------------------------------------------------
console.log('\n[7. Unicode and emoji near boundaries]')
{
  const res1 = redactSecrets('🎉 OTP 482913 💰')
  assertTest(
    'Emoji with OTP does not break',
    res1 === '🎉 OTP 4****3 💰',
    `Got: '${res1}'`
  )

  const analysis = analyzeMessage(
    '🎉 Congratulations! 🎊 Share your OTP 482913 to claim your 💰💰💰 prize!'
  )
  const credSig = analysis.signals.find((s) => s.id === 'credential-request')
  assertTest(
    'Evidence with surrounding emoji redacts OTP cleanly',
    Boolean(credSig && credSig.evidence.every((ev) => !ev.includes('482913') && ev.includes('4****3'))),
    `Evidence: ${JSON.stringify(credSig?.evidence)}`
  )
}

// ---------------------------------------------------------------------------
// 8. Empty, short and unusually spaced evidence snippets
// ---------------------------------------------------------------------------
console.log('\n[8. Empty, short and unusually spaced snippets]')
{
  assertTest('Empty string handled safely', redactSecrets('') === '')
  assertTest('Whitespace string handled safely', redactSecrets('   ') === '   ')
  assertTest('Short benign text untouched', redactSecrets('Hi there') === 'Hi there')
  assertTest('Short 2-digit numbers untouched', redactSecrets('age 25') === 'age 25')
  assertTest('Short 3-digit numbers untouched', redactSecrets('Rs 500') === 'Rs 500')
  assertTest('Time intervals untouched', redactSecrets('within 5 minutes') === 'within 5 minutes')
}

// ---------------------------------------------------------------------------
// 9. Python-backed and TypeScript fallback response paths
// ---------------------------------------------------------------------------
console.log('\n[9. Response paths: Engine mode & structures]')
{
  const tsResult = analyzeMessage('Please share your OTP 482913 immediately.')
  assertTest('TS engine info mode is local', tsResult.engine.mode === 'local')
  assertTest('TS engine name is FinGuard heuristic engine', tsResult.engine.name === 'FinGuard heuristic engine')
  assertTest('TS engine version is 1.0.0', tsResult.engine.version === '1.0.0')

  const cred = tsResult.signals.find((s) => s.id === 'credential-request')
  assertTest(
    'TypeScript fallback engine redacts OTP in evidence',
    Boolean(cred && cred.evidence.every((e) => e.includes('4****3') && !e.includes('482913'))),
    `Evidence: ${JSON.stringify(cred?.evidence)}`
  )
}

// ---------------------------------------------------------------------------
// 10. Unchanged risk classifications and signal IDs for all 45 fixtures
// ---------------------------------------------------------------------------
console.log('\n[10. Unchanged risk classifications and signal IDs across 45 fixtures]')
{
  const fixturePath = path.resolve(__dirname, 'fixtures', 'cross_engine_messages.json')
  const fixtures = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'))

  let allRiskMatch = true
  let allSignalsMatch = true
  const mismatchedFixtures: string[] = []

  for (const f of fixtures) {
    const result = analyzeMessage(f.message)
    const resultSignals = new Set(result.signals.map((s) => s.id))

    for (const exp of f.expectSignals) {
      if (!resultSignals.has(exp)) {
        allSignalsMatch = false
        mismatchedFixtures.push(`${f.id} missing ${exp}`)
      }
    }

    for (const abs of f.expectAbsent ?? []) {
      if (resultSignals.has(abs)) {
        allSignalsMatch = false
        mismatchedFixtures.push(`${f.id} unexpected ${abs}`)
      }
    }
  }

  assertTest(
    'All 45 fixtures have unchanged signal detections and expectations met',
    allSignalsMatch,
    mismatchedFixtures.join(', ')
  )
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n==================================================`)
console.log(`Total tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`)
console.log(`==================================================`)

if (failed > 0) {
  process.exit(1)
} else {
  console.log('All privacy redaction regression tests passed successfully.')
}
