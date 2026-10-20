import type { ReactNode } from 'react'

export function SectionHeading({
  id,
  eyebrow,
  title,
  children,
}: {
  id: string
  eyebrow: string
  title: ReactNode
  children?: ReactNode
}) {
  return (
    <div className="flex max-w-3xl flex-col gap-5">
      <p className="flex items-center gap-4 font-mono text-xs tracking-[0.18em] text-muted-foreground uppercase">
        <span aria-hidden="true" className="h-px w-10 bg-muted-foreground/60" />
        {eyebrow}
      </p>
      <h2 id={id} className="text-4xl leading-[1.05] font-light tracking-[-0.03em] text-balance md:text-6xl">
        {title}
      </h2>
      {children && <div className="max-w-xl text-lg leading-relaxed text-muted-foreground text-pretty">{children}</div>}
    </div>
  )
}
