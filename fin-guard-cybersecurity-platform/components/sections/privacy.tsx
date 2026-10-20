import { Reveal } from '@/components/reveal'
import { SectionHeading } from './section-heading'

const PRINCIPLES = [
  {
    title: 'Minimal collection',
    body: 'Only the message text you choose to submit is processed. No account, name, phone number, or contact list is required.',
  },
  {
    title: 'No raw message storage',
    body: 'Submitted text is analyzed in memory and discarded once the result is returned. It is not written to a database, logs, or browser storage.',
  },
  {
    title: 'Screenshots stay on your device',
    body: 'Text extraction from screenshots runs in your browser. The image itself is never uploaded.',
  },
  {
    title: 'Never your secrets',
    body: 'FinGuard will never ask for your UPI PIN, OTP, CVV, card number, or banking password. If anything does, it is not us.',
  },
]

export function Privacy() {
  return (
    <section id="privacy" aria-labelledby="privacy-title" className="relative overflow-hidden border-b border-border bg-surface/40">
      <div aria-hidden="true" className="absolute inset-0 bg-grid opacity-60" />
      <div className="relative mx-auto max-w-7xl px-5 py-24 md:px-8 md:py-36">
        <Reveal>
          <SectionHeading id="privacy-title" eyebrow="Privacy by design" title="Protection shouldn’t require exposure.">
            The messages people check are often personal. FinGuard is designed to need as little of
            them as possible.
          </SectionHeading>
        </Reveal>

        <div className="mt-16 grid gap-px overflow-hidden rounded-2xl border border-border bg-border sm:grid-cols-2 md:mt-24">
          {PRINCIPLES.map((p, i) => (
            <Reveal key={p.title} delay={i * 80} className="bg-background p-8 md:p-10">
              <h3 className="text-xl font-light tracking-[-0.01em] text-foreground">{p.title}</h3>
              <p className="mt-3 leading-relaxed text-muted-foreground">{p.body}</p>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  )
}
