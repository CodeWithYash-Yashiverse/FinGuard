import Image from 'next/image'
import { ArrowRight } from 'lucide-react'
import { buttonStyles } from '@/lib/button-styles'
import { cn } from '@/lib/utils'

const INDICATORS = [
  { label: 'Message & link analysis', detail: 'SMS, UPI, email, URLs' },
  { label: 'Evidence-based warnings', detail: 'Every flag shows its source' },
  { label: 'Privacy-first design', detail: 'Messages are not stored' },
]

export function Hero() {
  return (
    <section className="relative isolate flex min-h-[100svh] flex-col overflow-hidden border-b border-border">
      <div aria-hidden="true" className="absolute inset-0 -z-20 bg-grid" />
      <div aria-hidden="true" className="absolute inset-y-0 right-0 -z-10 w-full md:w-[70%]">
        <Image
          src="/images/hero-shield.png"
          alt=""
          fill
          priority
          sizes="(min-width: 768px) 70vw, 100vw"
          className="object-cover object-[70%_center] opacity-50 md:opacity-90"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-background via-background/40 to-transparent" />
        <div className="absolute inset-0 bg-gradient-to-t from-background via-transparent to-background/60" />
      </div>

      <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col justify-center px-5 pt-28 pb-12 md:px-8 md:pt-32">
        <p className="flex items-center gap-4 font-mono text-xs tracking-[0.18em] text-muted-foreground uppercase">
          <span aria-hidden="true" className="h-px w-10 bg-muted-foreground/60" />
          Intelligent digital payment protection
        </p>

        <h1 className="mt-8 max-w-4xl text-5xl leading-[0.98] font-light tracking-[-0.035em] text-balance sm:text-6xl md:text-7xl lg:text-[5.75rem]">
          Trust the payment.
          <br />
          <span className="text-primary">Verify the message.</span>
        </h1>

        <p className="mt-8 max-w-xl text-lg leading-relaxed text-muted-foreground text-pretty">
          Understand suspicious payment messages, uncover scam warning signs, and make safer digital
          payment decisions—with explanations you can actually understand.
        </p>

        <div className="mt-10 flex flex-col gap-3 sm:flex-row">
          <a href="#checker" className={cn(buttonStyles.primary, buttonStyles.sizeMd, 'group')}>
            Check a Message
            <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
          </a>
          <a href="#protection" className={cn(buttonStyles.ghost, buttonStyles.sizeMd)}>
            Explore Protection
          </a>
        </div>
      </div>

      <div className="mx-auto w-full max-w-7xl px-5 pb-10 md:px-8 md:pb-14">
        <ul className="grid gap-6 border-t border-border/70 pt-8 sm:grid-cols-3 sm:gap-10">
          {INDICATORS.map((item) => (
            <li key={item.label} className="flex flex-col gap-1.5">
              <span className="flex items-center gap-2 text-[15px] text-foreground">
                <span aria-hidden="true" className="size-1.5 rounded-full bg-primary" />
                {item.label}
              </span>
              <span className="pl-3.5 font-mono text-xs text-muted-foreground">{item.detail}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
