import { RotateCcw } from 'lucide-react'
import type { AnalysisResult } from '@/lib/analysis/types'
import { buttonStyles } from '@/lib/button-styles'
import { cn } from '@/lib/utils'
import { RiskIndicator } from './risk-indicator'
import { SignalList } from './signal-list'

export function AnalysisResults({ result, onReset }: { result: AnalysisResult; onReset: () => void }) {
  const analyzedAt = new Date(result.analyzedAt)

  return (
    <article
      aria-labelledby="result-title"
      className="mb-20 overflow-hidden rounded-2xl border border-border bg-background animate-in fade-in slide-in-from-bottom-2 duration-500 motion-reduce:animate-none md:mb-28"
    >
      <header className="border-b border-border p-6 md:p-10">
        <RiskIndicator level={result.riskLevel} />
        <p className="mt-5 max-w-3xl text-lg leading-relaxed text-muted-foreground text-pretty">{result.summary}</p>
      </header>

      <div className="grid lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <section aria-labelledby="signals-title" className="border-b border-border p-6 md:p-10 lg:border-r lg:border-b-0">
          <h3 id="signals-title" className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">
            Warning signs found ({result.signals.length})
          </h3>
          {result.signals.length > 0 ? (
            <SignalList signals={result.signals} />
          ) : (
            <p className="mt-6 text-sm leading-relaxed text-muted-foreground">
              None of FinGuard&apos;s checks matched this message. That is not a guarantee of safety — new
              scam formats appear constantly.
            </p>
          )}
        </section>

        <div className="flex flex-col">
          <section aria-labelledby="steps-title" className="border-b border-border p-6 md:p-10">
            <h3 id="steps-title" className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">
              Recommended next steps
            </h3>
            <ol className="mt-6 flex flex-col gap-4">
              {result.nextSteps.map((step, i) => (
                <li key={step} className="flex gap-4 text-[15px] leading-relaxed text-foreground">
                  <span className="font-mono text-xs leading-6 text-primary tabular-nums">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </section>

          {result.verification.length > 0 && (
            <section aria-labelledby="verify-title" className="p-6 md:p-10">
              <h3 id="verify-title" className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">
                How to verify safely
              </h3>
              <ul className="mt-6 flex flex-col gap-3">
                {result.verification.map((item) => (
                  <li key={item} className="flex gap-3 text-sm leading-relaxed text-muted-foreground">
                    <span aria-hidden="true" className="mt-2 size-1 shrink-0 rounded-full bg-muted-foreground" />
                    {item}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>

      <footer className="flex flex-col gap-4 border-t border-border bg-surface/50 px-6 py-5 sm:flex-row sm:items-center sm:justify-between md:px-10">
        <p className="font-mono text-xs leading-relaxed text-muted-foreground">
          {result.engine.name} v{result.engine.version} ·{' '}
          <time dateTime={result.analyzedAt}>{analyzedAt.toLocaleTimeString()}</time> · Indicators, not
          proof of fraud.
        </p>
        <button type="button" onClick={onReset} className={cn(buttonStyles.primary, buttonStyles.sizeSm)}>
          <RotateCcw className="size-3.5" aria-hidden="true" />
          Check Another Message
        </button>
      </footer>
    </article>
  )
}
