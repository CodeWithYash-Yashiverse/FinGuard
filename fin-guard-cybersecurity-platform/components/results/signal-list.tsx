import type { Severity, WarningSignal } from '@/lib/analysis/types'
import { cn } from '@/lib/utils'

const SEVERITY: Record<Severity, { label: string; className: string; marks: string }> = {
  high: { label: 'High', className: 'border-danger/40 text-danger', marks: '▲▲▲' },
  medium: { label: 'Medium', className: 'border-caution/40 text-caution', marks: '▲▲' },
  low: { label: 'Low', className: 'border-border text-muted-foreground', marks: '▲' },
}

export function SignalList({ signals }: { signals: WarningSignal[] }) {
  return (
    <ul className="mt-6 flex flex-col divide-y divide-border">
      {signals.map((signal) => {
        const sev = SEVERITY[signal.severity]
        return (
          <li key={signal.id} className="flex flex-col gap-3 py-6 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-center gap-3">
              <span
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] tracking-wider uppercase',
                  sev.className,
                )}
              >
                <span aria-hidden="true" className="text-[8px]">{sev.marks}</span>
                {sev.label}
                <span className="sr-only"> severity</span>
              </span>
              <span className="font-mono text-[11px] tracking-wider text-muted-foreground uppercase">
                {signal.category}
              </span>
            </div>
            <h4 className="text-lg leading-snug text-foreground">{signal.title}</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">{signal.explanation}</p>
            {signal.evidence.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <span className="font-mono text-[11px] tracking-wider text-muted-foreground/80 uppercase">
                  Found in message
                </span>
                {signal.evidence.map((e) => (
                  <q
                    key={e}
                    className="block rounded-md border-l-2 border-border bg-white/[0.02] px-3 py-2 font-mono text-xs leading-relaxed break-words text-foreground/90 before:content-none after:content-none"
                  >
                    {e}
                  </q>
                ))}
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
