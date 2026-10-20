import Link from 'next/link'

export function LogoMark({ className = 'size-6' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={className}>
      <path
        d="M12 2.75 4.75 5.5v5.62c0 4.6 3.06 8.6 7.25 10.13 4.19-1.53 7.25-5.53 7.25-10.13V5.5L12 2.75Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="m8.75 12.1 2.3 2.3 4.2-4.65"
        stroke="var(--primary)"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function Logo() {
  return (
    <Link href="/" className="flex items-center gap-2.5 text-foreground" aria-label="FinGuard home">
      <LogoMark />
      <span className="text-lg font-medium tracking-tight">FinGuard</span>
    </Link>
  )
}
