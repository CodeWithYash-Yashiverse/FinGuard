import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { RiskLevel } from '@/lib/analysis/types'
import { cn } from '@/lib/utils'

const LEVELS: Record<
  RiskLevel,
  { label: string; filled: number; tone: string; bar: string; Icon: typeof ShieldAlert; code: string }
> = {
  high_risk: { label: 'High Risk', filled: 3, tone: 'text-danger', bar: 'bg-danger', Icon: ShieldAlert, code: 'LEVEL 3 / 3' },
  suspicious: { label: 'Suspicious', filled: 2, tone: 'text-caution', bar: 'bg-caution', Icon: ShieldQuestion, code: 'LEVEL 2 / 3' },
  no_strong_signs: {
    label: 'No Strong Warning Signs Detected',
    filled: 1,
    tone: 'text-primary',
    bar: 'bg-primary',
    Icon: ShieldCheck,
    code: 'LEVEL 1 / 3',
  },
}

export function RiskIndicator({ level }: { level: RiskLevel }) {
  const config = LEVELS[level]
  const { Icon } = config

  return (
    <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
      <div className="flex items-start gap-4">
        <span className={cn('flex size-12 shrink-0 items-center justify-center rounded-full border border-current/30', config.tone)}>
          <Icon className="size-5" aria-hidden="true" />
        </span>
        <div>
          <p className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">Assessment</p>
          <h2 id="result-title" className={cn('mt-1 text-3xl font-light tracking-[-0.02em] md:text-4xl', config.tone)}>
            {config.label}
          </h2>
        </div>
      </div>

      <div className="flex flex-col gap-2 sm:items-end">
        <div
          role="meter"
          aria-label="Risk level"
          aria-valuemin={1}
          aria-valuemax={3}
          aria-valuenow={config.filled}
          aria-valuetext={config.label}
          className="flex gap-1.5"
        >
          {[1, 2, 3].map((n) => (
            <span
              key={n}
              className={cn(
                'h-1.5 w-10 rounded-full',
                n <= config.filled ? config.bar : 'bg-white/10',
              )}
            />
          ))}
        </div>
        <span className="font-mono text-[11px] tracking-wider text-muted-foreground">{config.code}</span>
      </div>
    </div>
  )
}
