import type {
  AnalysisResult,
  RiskLevel,
  Severity,
  SignalCategory,
  WarningSignal,
} from './types'

export const ENGINE_NAME = 'FinGuard heuristic engine'
export const ENGINE_VERSION = '1.0.0'

interface Rule {
  id: string
  category: SignalCategory
  title: string
  severity: Severity
  explanation: string
  patterns: RegExp[]
  requires?: RegExp
  skipIfPrecededBy?: RegExp
}

const RULES: Rule[] = [
  {
    id: 'credential-request',
    category: 'credentials',
    title: 'Asks you to share an OTP, PIN, or password',
    severity: 'high',
    explanation:
      'Banks, payment apps, and government agencies never ask you to share an OTP, UPI PIN, CVV, or password. Anyone who has these can move money out of your account.',
    patterns: [
      /\b(share|send|tell|provide|give|forward|reply(?: with)?|read out|confirm|sms)\b[^.\n!?]{0,40}?\b(otp|one[\s-]?time[\s-]?(?:password|passcode|code|pin)|upi\s?pin|m-?pin|atm pin|cvv|cvc|password|passcode|verification code|card number|card details)\b/gi,
    ],
    skipIfPrecededBy: /\b(do not|don't|dont|never|not to|no one will)\s*$/i,
  },
  {
    id: 'pin-to-receive',
    category: 'payment',
    title: 'Claims you need a PIN or QR scan to receive money',
    severity: 'high',
    explanation:
      'You never need to enter your UPI PIN, scan a QR code, or approve a request to receive money. Entering your PIN always sends money out of your account.',
    patterns: [
      /\b(enter|input|type|use)\b[^.\n]{0,30}\b(upi\s?)?pin\b[^.\n]{0,50}\b(receive|get|claim|credit(?:ed)?|refund|cashback|prize)\b/gi,
      /\b(receive|claim|get)\b[^.\n]{0,40}\b(enter|scan|approve|accept)\b[^.\n]{0,30}\b(pin|qr|request)\b/gi,
      /\bscan\b[^.\n]{0,25}\bqr\b[^.\n]{0,50}\b(receive|get|claim|refund|cashback|prize|credit)\b/gi,
    ],
  },
  {
    id: 'remote-access',
    category: 'pattern',
    title: 'Asks you to install a screen-sharing or remote-access app',
    severity: 'high',
    explanation:
      'Remote-access apps let another person see and control your phone, including your banking apps and OTPs. Legitimate support teams do not need this to resolve payment issues.',
    patterns: [
      /\b(anydesk|any desk|teamviewer|quick ?support|rustdesk|airdroid|screen ?shar(?:e|ing)|remote (?:access|control) app)\b/gi,
    ],
  },
  {
    id: 'legal-threat',
    category: 'urgency',
    title: 'Threatens arrest or legal action',
    severity: 'high',
    explanation:
      'Police, courts, and tax authorities do not demand payment over messages or calls, and there is no such thing as a "digital arrest". Fear is used to stop you from thinking clearly.',
    patterns: [
      /\b(digital arrest|arrest warrant|you will be arrested|legal action will be|fir (?:has been|will be) (?:filed|registered)|case (?:has been )?registered against you|money laundering case)\b/gi,
    ],
  },
  {
    id: 'urgency',
    category: 'urgency',
    title: 'Creates pressure to act immediately',
    severity: 'medium',
    explanation:
      'Scammers rush you so you act before verifying. A genuine organisation will give you time to check through official channels.',
    patterns: [
      /\b(urgent(?:ly)?|immediately|right away|asap|act now|last (?:chance|warning|reminder)|final (?:notice|warning|reminder)|within \d+\s?(?:min(?:ute)?s?|hours?|hrs?)|today itself|before midnight|expir(?:es|ing) (?:today|tonight|soon|in))\b/gi,
    ],
  },
  {
    id: 'account-threat',
    category: 'urgency',
    title: 'Warns that your account or service will be blocked',
    severity: 'medium',
    explanation:
      'Messages claiming your account, card, SIM, or KYC will be blocked are a common way to push people into clicking links or sharing details.',
    patterns: [
      /\b(account|a\/c|card|kyc|sim|mobile number|connection|electricity|power|wallet|pan)\b[^.\n]{0,40}\b(block(?:ed)?|suspend(?:ed)?|deactivat(?:e|ed)|frozen|freeze|disconnect(?:ed)?|terminat(?:e|ed)|on hold)\b/gi,
      /\bkyc\b[^.\n]{0,20}\b(update|pending|expired|incomplete|verification)\b/gi,
    ],
  },
  {
    id: 'payment-demand',
    category: 'payment',
    title: 'Requests a payment, fee, or approval',
    severity: 'medium',
    explanation:
      'Unexpected requests to pay a fee, deposit, or "release" charge are a hallmark of prize, job, delivery, and loan scams. Verify any request for money independently.',
    patterns: [
      /\b(pay|transfer|deposit|send)\b[^.\n]{0,30}(₹|\brs\.?|\binr\b|\brupees\b|\$|\busd\b|\bamount\b|\bfee\b|\bcharges?\b)/gi,
      /\b(processing|registration|release|clearance|customs|security|refundable|verification|delivery)\s+(fee|charges?|deposit)\b/gi,
      /\b(collect request|approve (?:the )?(?:payment )?request|accept (?:the )?payment request)\b/gi,
    ],
  },
  {
    id: 'too-good',
    category: 'pattern',
    title: 'Offers a prize, refund, or income that seems too good',
    severity: 'medium',
    explanation:
      'Unexpected winnings, cashback, refunds, or easy-income offers are used to lower your guard before asking for a fee or your details.',
    patterns: [
      /\b(you(?:'ve| have)? won|winner|lottery|lucky draw|jackpot|claim (?:your )?(?:prize|reward|gift)|free gift|reward points? (?:expir\w*|redeem\w*))\b/gi,
      /\b(work from home|part[- ]time job|earn\s*(?:₹|rs\.?|inr)?\s?\d[\d,]*\s*(?:per|\/|a|daily)\s*(?:day|hour|task)?|like (?:videos|youtube videos)|daily (?:income|payout)|task[- ]based)\b/gi,
    ],
  },
  {
    id: 'impersonation',
    category: 'impersonation',
    title: 'Claims to be from a bank, payment app, or authority',
    severity: 'medium',
    explanation:
      'Anyone can put a bank, brand, or government name in a message. A claim of identity is not proof of identity — confirm it using contact details you find yourself.',
    patterns: [
      /\b(sbi|state bank|hdfc|icici|axis bank|kotak|pnb|bank of baroda|rbi|reserve bank|npci|paytm|phonepe|phone pe|google pay|gpay|bhim|amazon|flipkart|income tax|customs|cbi|police|cyber cell|trai|fedex|dhl|india post|courier|electricity board|customer care|bank manager|bank official)\b/gi,
    ],
    requires:
      /\b(account|kyc|refund|verify|verification|update|block|suspend|officer|department|parcel|bill|reward|cashback|pending|link|click)\b/i,
  },
  {
    id: 'secrecy',
    category: 'pattern',
    title: 'Asks you to keep the conversation secret',
    severity: 'medium',
    explanation:
      'Being told not to tell family or your bank, or to stay on the call, is a pressure tactic designed to stop someone from warning you.',
    patterns: [
      /\b(don'?t tell (?:anyone|your family|your bank)|do not (?:tell|inform) (?:anyone|your family|your bank)|keep (?:this|it) (?:confidential|secret)|don'?t (?:disconnect|hang up)|stay on the (?:call|line))\b/gi,
    ],
  },
  {
    id: 'callback-number',
    category: 'impersonation',
    title: 'Asks you to call or message an unverified number',
    severity: 'low',
    explanation:
      'Numbers inside a suspicious message may connect you directly to the scammer. Use the number printed on your card or the official website instead.',
    patterns: [/\b(call|whatsapp|contact|dial|message)\b[^.\n]{0,30}(\+?\d[\d\s-]{8,}\d)/gi],
  },
]

const URL_PATTERN =
  /\b((?:https?:\/\/|www\.)[^\s<>"']+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|xyz|top|click|live|online|info|icu|buzz|site|me|ly|co|io|app|link|shop|vip|cc|tk|ml|ga|cf|gq)(?:\/[^\s<>"']*)?)/gi

const SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'cutt.ly',
  'rb.gy',
  'ow.ly',
  'shorturl.at',
  'tiny.cc',
  's.id',
  'v.gd',
  'rebrand.ly',
]

const UNUSUAL_TLDS = [
  'xyz', 'top', 'click', 'live', 'online', 'info', 'icu', 'buzz', 'site', 'vip', 'shop', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'link',
]

const BRAND_DOMAINS: Record<string, string[]> = {
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in', 'sbicard.com'],
  hdfc: ['hdfcbank.com', 'hdfc.bank.in'],
  icici: ['icicibank.com', 'icici.bank.in'],
  axis: ['axisbank.com', 'axis.bank.in'],
  kotak: ['kotak.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  gpay: ['google.com', 'pay.google.com'],
  amazon: ['amazon.in', 'amazon.com'],
  flipkart: ['flipkart.com'],
  npci: ['npci.org.in'],
  rbi: ['rbi.org.in'],
  incometax: ['incometax.gov.in'],
  indiapost: ['indiapost.gov.in'],
}

const SEVERITY_WEIGHT: Record<Severity, number> = { high: 3, medium: 2, low: 1 }

/**
 * Partially mask sensitive numeric sequences in evidence snippets.
 *
 * Prevents full OTPs, PINs, card numbers, phone numbers and long reference
 * numbers from being displayed in evidence excerpts while preserving ordinary
 * monetary amounts (e.g. "Rs 1500", "₹2500", "$1500") when clearly formatted as currency.
 */
export function redactSecrets(text: string): string {
  if (!text || typeof text !== 'string') return text

  // 1. Identify currency amount spans to protect them from redaction
  const currencyRegex =
    /(?:(?:₹|\brs\.?|\binr\b|\brupees\b|\$|\busd\b|\beur\b|€|£|\bgbp\b)\s*[\d,]+(?:\.\d+)?|[\d,]+(?:\.\d+)?\s*(?:₹|\brs\.?|\binr\b|\brupees\b|\$|\busd\b|\beur\b|€|£|\bgbp\b|\/-|\/(?:day|hour|month|year)\b|\bper\s+(?:day|hour|month|year|task)\b))/gi

  const currencySpans: Array<[number, number]> = []
  for (const m of text.matchAll(currencyRegex)) {
    if (m.index !== undefined) {
      currencySpans.push([m.index, m.index + m[0].length])
    }
  }

  const isCurrency = (start: number, end: number): boolean => {
    return currencySpans.some(([cStart, cEnd]) => start >= cStart && end <= cEnd)
  }

  // 2. Formatted 16-digit card numbers (e.g. 4111 2222 3333 4444 or 4111-2222-3333-4444)
  let out = text.replace(
    /\b(\d{4})([-\s])(\d{4})([-\s])(\d{4})([-\s])(\d{4})\b/g,
    (match, g1, s1, _g2, s2, _g3, s3, g4, offset) => {
      if (isCurrency(offset, offset + match.length)) return match
      return `${g1[0]}***${s1}****${s2}****${s3}***${g4[3]}`
    }
  )

  // 3. Formatted 10-digit phone numbers with 3-3-4 pattern (e.g. 987-654-3210 or 987 654 3210)
  out = out.replace(
    /\b(\d{3})([-\s])(\d{3})([-\s])(\d{4})\b/g,
    (match, g1, s1, _g2, s2, g3, offset) => {
      if (isCurrency(offset, offset + match.length)) return match
      return `${g1[0]}**${s1}***${s2}**${g3.slice(-2)}`
    }
  )

  // 4. Standalone 4+ digit sequences (OTPs, PINs, unspaced cards, refs, phone blocks like 98765 in +91 98765 43210)
  out = out.replace(/\d{4,}/g, (match, offset) => {
    if (isCurrency(offset, offset + match.length)) {
      return match
    }
    return match[0] + '*'.repeat(match.length - 2) + match[match.length - 1]
  })

  return out
}

function snippet(text: string, index: number, length: number): string {
  const pad = 28
  const start = Math.max(0, index - pad)
  const end = Math.min(text.length, index + length + pad)
  let out = text.slice(start, end).replace(/\s+/g, ' ').trim()
  if (start > 0) out = `…${out}`
  if (end < text.length) out = `${out}…`
  return redactSecrets(out)
}

function runRule(rule: Rule, text: string): WarningSignal | null {
  if (rule.requires && !rule.requires.test(text)) return null
  const evidence = new Set<string>()

  for (const pattern of rule.patterns) {
    pattern.lastIndex = 0
    for (const match of text.matchAll(pattern)) {
      const index = match.index ?? 0
      if (rule.skipIfPrecededBy) {
        const before = text.slice(Math.max(0, index - 24), index)
        if (rule.skipIfPrecededBy.test(before)) continue
      }
      evidence.add(snippet(text, index, match[0].length))
      if (evidence.size >= 3) break
    }
    if (evidence.size >= 3) break
  }

  if (evidence.size === 0) return null
  return {
    id: rule.id,
    category: rule.category,
    title: rule.title,
    severity: rule.severity,
    explanation: rule.explanation,
    evidence: [...evidence],
  }
}

function hostOf(raw: string): string | null {
  const cleaned = raw.replace(/[),.;:!?'"\]]+$/, '')
  try {
    const url = new URL(/^https?:\/\//i.test(cleaned) ? cleaned : `http://${cleaned}`)
    return url.hostname.toLowerCase()
  } catch {
    return null
  }
}

function matchesDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`)
}

function analyzeLinks(text: string): WarningSignal[] {
  const links = [...text.matchAll(URL_PATTERN)].map((m) => m[0].replace(/[),.;:!?'"\]]+$/, ''))
  if (links.length === 0) return []

  const findings: Record<string, { severity: Severity; title: string; explanation: string; evidence: Set<string> }> = {}
  const add = (id: string, severity: Severity, title: string, explanation: string, link: string) => {
    findings[id] ??= { severity, title, explanation, evidence: new Set() }
    if (findings[id].evidence.size < 3) findings[id].evidence.add(link)
  }

  for (const link of links) {
    const host = hostOf(link)
    if (!host) continue
    const bareHost = host.replace(/^www\./, '')
    const tld = bareHost.split('.').pop() ?? ''

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bareHost)) {
      add('link-ip', 'high', 'Link points to a raw IP address', 'Legitimate banks and payment services use named domains. A link made of numbers hides who operates the site.', link)
    }
    if (bareHost.includes('xn--')) {
      add('link-punycode', 'high', 'Link uses look-alike characters', 'This domain uses encoded characters that can imitate a familiar brand name letter for letter.', link)
    }
    if (SHORTENERS.some((s) => matchesDomain(bareHost, s))) {
      add('link-shortener', 'medium', 'Shortened link hides the real destination', 'Link shorteners conceal where you will actually land. Payment providers rarely send shortened links for account actions.', link)
    }
    if (UNUSUAL_TLDS.includes(tld)) {
      add('link-tld', 'medium', 'Link uses an unusual domain ending', `Domains ending in ".${tld}" are cheap to register and are frequently used for short-lived scam sites.`, link)
    }
    const flatHost = bareHost.replace(/[-.]/g, '')
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      if (flatHost.includes(brand) && !domains.some((d) => matchesDomain(bareHost, d))) {
        add('link-lookalike', 'high', 'Link imitates a known brand but is not its official domain', `The address mentions "${brand}" but is not an official ${brand.toUpperCase()} domain. Look-alike sites are built to collect login details and card numbers.`, link)
        break
      }
    }
    if (/^http:\/\//i.test(link)) {
      add('link-insecure', 'low', 'Link is not encrypted', 'This link uses http instead of https. A payment or login page should never be served without encryption.', link)
    }
  }

  const signals: WarningSignal[] = Object.entries(findings).map(([id, f]) => ({
    id,
    category: 'link',
    title: f.title,
    severity: f.severity,
    explanation: f.explanation,
    evidence: [...f.evidence],
  }))

  if (signals.length === 0) {
    signals.push({
      id: 'link-present',
      category: 'link',
      title: 'Contains a link',
      severity: 'low',
      explanation:
        'No specific problem was found with this link, but links in unexpected payment messages should not be trusted. Type the official address yourself instead.',
      evidence: links.slice(0, 3),
    })
  }
  return signals
}

function classify(signals: WarningSignal[]): RiskLevel {
  const count = (s: Severity) => signals.filter((x) => x.severity === s).length
  const high = count('high')
  const medium = count('medium')
  const low = count('low')
  if (high >= 1 || medium >= 3) return 'high_risk'
  if (medium >= 1 || low >= 2) return 'suspicious'
  return 'no_strong_signs'
}

function buildSummary(level: RiskLevel, signals: WarningSignal[]): string {
  const n = signals.length
  const plural = n === 1 ? 'sign' : 'signs'
  switch (level) {
    case 'high_risk':
      return `We found ${n} warning ${plural}, including patterns strongly associated with payment scams. Do not act on this message until you have verified it independently.`
    case 'suspicious':
      return `We found ${n} warning ${plural} that are common in scam messages. This is not proof of fraud, but the message deserves caution and independent verification.`
    case 'no_strong_signs':
      return n > 0
        ? 'We did not find strong warning signs, only a minor indicator. This does not mean the message is safe — verify any request for money or information through official channels.'
        : 'We did not find strong warning signs. This does not mean the message is safe — some scams contain no obvious indicators. Verify any request for money or information through official channels.'
  }
}

function buildNextSteps(level: RiskLevel, signals: WarningSignal[]): string[] {
  const ids = new Set(signals.map((s) => s.id))
  const categories = new Set(signals.map((s) => s.category))
  const steps: string[] = []

  if (ids.has('credential-request')) {
    steps.push('Do not share any OTP, UPI PIN, CVV, or password — with anyone, for any reason.')
  }
  if (ids.has('pin-to-receive') || ids.has('payment-demand')) {
    steps.push('Do not send money, enter your PIN, scan the QR code, or approve any collect request from this message.')
  }
  if (categories.has('link')) {
    steps.push('Do not open the link. If you need to check your account, type the official website address yourself or use the official app.')
  }
  if (ids.has('remote-access')) {
    steps.push('Do not install any app the sender recommends. If you already did, uninstall it and change your banking passwords from a different device.')
  }
  if (ids.has('legal-threat') || ids.has('secrecy')) {
    steps.push('End the conversation. Talk to someone you trust before doing anything — real authorities will not object.')
  }
  if (level === 'high_risk') {
    steps.push('If you already shared details or sent money, call your bank immediately using the number on your card or their official website, and ask them to block the transaction.')
    steps.push('Report the message to your national cybercrime reporting service (see Safety & Reporting below).')
  }
  if (level === 'suspicious') {
    steps.push('Pause before responding. Contact the organisation through a phone number or website you find independently.')
  }
  if (level === 'no_strong_signs') {
    steps.push('If the message asks for money or personal information, still confirm it through official channels before acting.')
  }
  return steps
}

const VERIFICATION_GUIDANCE = [
  'Find the organisation’s contact details yourself — the back of your card, your official banking app, or a website address you type manually.',
  'Never use phone numbers, links, or QR codes provided inside the suspicious message.',
  'Check the transaction or request inside your official bank or UPI app, not through a link.',
  'Remember: receiving money never requires your PIN, an OTP, or scanning a QR code.',
]

export function analyzeMessage(message: string): AnalysisResult {
  const text = message.normalize('NFKC')
  const signals: WarningSignal[] = []

  for (const rule of RULES) {
    const signal = runRule(rule, text)
    if (signal) signals.push(signal)
  }
  signals.push(...analyzeLinks(text))
  signals.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity])

  const riskLevel = classify(signals)
  return {
    riskLevel,
    summary: buildSummary(riskLevel, signals),
    signals,
    nextSteps: buildNextSteps(riskLevel, signals),
    verification: VERIFICATION_GUIDANCE,
    engine: { name: ENGINE_NAME, version: ENGINE_VERSION, mode: 'local' },
    analyzedAt: new Date().toISOString(),
  }
}
