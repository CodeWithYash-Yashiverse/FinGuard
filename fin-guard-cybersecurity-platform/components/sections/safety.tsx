import { ArrowUpRight } from 'lucide-react'
import { Reveal } from '@/components/reveal'
import { SectionHeading } from './section-heading'

const VERIFY_STEPS = [
  'Stop. Don’t reply, click, scan, or call back from the message itself.',
  'Find the official contact details yourself — the number on the back of your card, your bank’s official app, or a website address you type manually.',
  'Check the request inside your official banking or UPI app. Real pending actions will appear there.',
  'Ask someone you trust. Scammers rely on isolation and speed.',
]

const IF_FRAUD = [
  'Call your bank immediately using its official number and ask them to block your card, UPI, or account and dispute the transaction.',
  'Change passwords and UPI PIN from a device you trust, and uninstall any app a caller asked you to install.',
  'Keep evidence: screenshots, sender numbers, transaction IDs, and timestamps.',
  'Report the incident to your national cybercrime authority as soon as possible — fast reporting improves the chance of recovering funds.',
]

const REPORTING = [
  {
    region: 'India',
    label: 'National Cyber Crime Helpline',
    detail: 'Call 1930',
    href: 'tel:1930',
  },
  {
    region: 'India',
    label: 'National Cyber Crime Reporting Portal',
    detail: 'cybercrime.gov.in',
    href: 'https://cybercrime.gov.in',
  },
  {
    region: 'India',
    label: 'Report suspected fraud communication (Chakshu)',
    detail: 'sancharsaathi.gov.in',
    href: 'https://sancharsaathi.gov.in',
  },
]

export function Safety() {
  return (
    <section id="safety" aria-labelledby="safety-title" className="border-b border-border">
      <div className="mx-auto max-w-7xl px-5 py-24 md:px-8 md:py-36">
        <Reveal>
          <SectionHeading id="safety-title" eyebrow="Safety & reporting" title="When in doubt, verify independently.">
            A result from FinGuard is a starting point. These steps work for any payment request, whether or
            not it was flagged.
          </SectionHeading>
        </Reveal>

        <div className="mt-16 grid gap-12 md:mt-24 lg:grid-cols-2 lg:gap-20">
          <Reveal>
            <h3 className="font-mono text-xs tracking-[0.16em] text-primary uppercase">Before you pay</h3>
            <StepList items={VERIFY_STEPS} />
          </Reveal>
          <Reveal delay={100}>
            <h3 className="font-mono text-xs tracking-[0.16em] text-danger uppercase">If you suspect fraud</h3>
            <StepList items={IF_FRAUD} />
          </Reveal>
        </div>

        <Reveal className="mt-20 rounded-2xl border border-border bg-surface/50 p-6 md:p-10">
          <div className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
            <h3 className="text-2xl font-light tracking-[-0.02em]">Where to report</h3>
            <p className="max-w-md text-sm text-muted-foreground">
              Outside India, contact your bank and your local police or national fraud reporting service.
            </p>
          </div>
          <ul className="mt-8 grid gap-px overflow-hidden rounded-xl border border-border bg-border md:grid-cols-3">
            {REPORTING.map((r) => (
              <li key={r.label} className="bg-background">
                <a
                  href={r.href}
                  target={r.href.startsWith('http') ? '_blank' : undefined}
                  rel={r.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                  className="group flex h-full flex-col gap-6 p-6 transition-colors hover:bg-white/[0.02]"
                >
                  <span className="flex items-center justify-between font-mono text-[11px] tracking-wider text-muted-foreground uppercase">
                    {r.region}
                    <ArrowUpRight className="size-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" aria-hidden="true" />
                  </span>
                  <span>
                    <span className="block text-foreground">{r.label}</span>
                    <span className="mt-1 block font-mono text-sm text-primary">{r.detail}</span>
                  </span>
                </a>
              </li>
            ))}
          </ul>
        </Reveal>
      </div>
    </section>
  )
}

function StepList({ items }: { items: string[] }) {
  return (
    <ol className="mt-6 border-t border-border">
      {items.map((item, i) => (
        <li key={item} className="flex gap-5 border-b border-border py-5 leading-relaxed">
          <span className="font-mono text-xs leading-7 text-muted-foreground tabular-nums">{String(i + 1).padStart(2, '0')}</span>
          <span className="text-foreground/90">{item}</span>
        </li>
      ))}
    </ol>
  )
}
