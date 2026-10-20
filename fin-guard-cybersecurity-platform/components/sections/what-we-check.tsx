import { Reveal } from '@/components/reveal'
import { SectionHeading } from './section-heading'

const CHECKS = [
  {
    code: 'LINK',
    title: 'Suspicious or misleading links',
    body: 'Look-alike brand domains, shortened URLs, raw IP addresses, unusual domain endings, and unencrypted pages.',
  },
  {
    code: 'URGENCY',
    title: 'Urgent demands for payment',
    body: 'Deadlines, threats of account blocking, legal intimidation, and pressure to act before you can verify.',
  },
  {
    code: 'CREDENTIALS',
    title: 'Requests for OTPs, PINs, or sensitive information',
    body: 'Any ask to share an OTP, UPI PIN, CVV, or password — and claims that you need a PIN to receive money.',
  },
  {
    code: 'IDENTITY',
    title: 'Impersonation and suspicious sender claims',
    body: 'Messages claiming to be your bank, a payment app, a courier, or a government authority, paired with account actions.',
  },
  {
    code: 'PATTERN',
    title: 'Common payment scam patterns',
    body: 'Prize and refund lures, task-based job offers, remote-access app requests, fee demands, and secrecy tactics.',
  },
]

export function WhatWeCheck() {
  return (
    <section id="protection" aria-labelledby="protection-title" className="border-b border-border">
      <div className="mx-auto grid max-w-7xl gap-16 px-5 py-24 md:px-8 md:py-36 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-20">
        <Reveal className="lg:sticky lg:top-32 lg:self-start">
          <SectionHeading id="protection-title" eyebrow="What FinGuard checks" title="Signals, explained.">
            <p>
              FinGuard looks for patterns that commonly appear in payment scams. Each one is an{' '}
              <span className="text-foreground">indicator, not definitive proof of fraud</span> — genuine
              messages can trigger them, and some scams trigger none.
            </p>
          </SectionHeading>
        </Reveal>

        <ul className="border-t border-border">
          {CHECKS.map((check, i) => (
            <li key={check.code} className="border-b border-border">
              <Reveal delay={i * 60} className="grid gap-3 py-8 sm:grid-cols-[9rem_1fr] sm:gap-8 md:py-10">
                <span className="font-mono text-xs tracking-[0.16em] text-primary">{check.code}</span>
                <div>
                  <h3 className="text-xl font-light tracking-[-0.01em] text-foreground md:text-2xl">{check.title}</h3>
                  <p className="mt-3 leading-relaxed text-muted-foreground">{check.body}</p>
                </div>
              </Reveal>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
