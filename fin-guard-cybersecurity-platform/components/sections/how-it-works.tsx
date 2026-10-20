import { Reveal } from '@/components/reveal'
import { SectionHeading } from './section-heading'

const STEPS = [
  {
    title: 'Submit a suspicious message',
    body: 'Paste the text of an SMS, UPI request, chat, or email — or extract it from a screenshot on your device.',
  },
  {
    title: 'Review the warning signs',
    body: 'See each indicator FinGuard detected, the exact words that triggered it, and why it matters.',
  },
  {
    title: 'Follow the safety steps',
    body: 'Get clear next actions and guidance for verifying the request through channels you can trust.',
  },
]

export function HowItWorks() {
  return (
    <section id="how-it-works" aria-labelledby="how-title" className="border-b border-border">
      <div className="mx-auto max-w-7xl px-5 py-24 md:px-8 md:py-36">
        <Reveal>
          <SectionHeading id="how-title" eyebrow="How it works" title="Three steps between a message and a decision.">
            No account, no setup. Built for the moment a message makes you hesitate.
          </SectionHeading>
        </Reveal>

        <ol className="mt-16 grid border-t border-border md:mt-24 md:grid-cols-3">
          {STEPS.map((step, i) => (
            <li
              key={step.title}
              className="border-b border-border py-10 md:border-b-0 md:py-12 md:pr-10 md:[&:not(:first-child)]:border-l md:[&:not(:first-child)]:pl-10"
            >
              <Reveal delay={i * 100}>
                <span className="font-mono text-sm text-primary tabular-nums">{String(i + 1).padStart(2, '0')}</span>
                <h3 className="mt-8 text-2xl font-light tracking-[-0.02em] text-foreground">{step.title}</h3>
                <p className="mt-4 leading-relaxed text-muted-foreground">{step.body}</p>
              </Reveal>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}
