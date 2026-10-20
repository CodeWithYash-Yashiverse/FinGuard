import { Logo } from '@/components/brand/logo'
import { NAV_ITEMS } from './nav-items'

export function SiteFooter() {
  return (
    <footer className="bg-background">
      <div className="mx-auto max-w-7xl px-5 py-16 md:px-8 md:py-20">
        <div className="flex flex-col gap-12 md:flex-row md:justify-between">
          <div className="max-w-sm">
            <Logo />
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              Plain-language scam awareness for digital payments.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-10 sm:gap-20">
            <nav aria-label="Footer">
              <p className="font-mono text-[11px] tracking-[0.16em] text-muted-foreground uppercase">Product</p>
              <ul className="mt-4 flex flex-col gap-3 text-sm">
                <li>
                  <a href="#checker" className="text-foreground/80 transition-colors hover:text-foreground">Check a Message</a>
                </li>
                {NAV_ITEMS.map((item) => (
                  <li key={item.href}>
                    <a href={item.href} className="text-foreground/80 transition-colors hover:text-foreground">
                      {item.label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
            <div>
              <p className="font-mono text-[11px] tracking-[0.16em] text-muted-foreground uppercase">Trust</p>
              <ul className="mt-4 flex flex-col gap-3 text-sm">
                <li>
                  <a href="#privacy" className="text-foreground/80 transition-colors hover:text-foreground">Privacy by design</a>
                </li>
                <li>
                  <a href="#safety" className="text-foreground/80 transition-colors hover:text-foreground">Report fraud</a>
                </li>
              </ul>
            </div>
          </div>
        </div>

        <div className="mt-16 flex flex-col gap-4 border-t border-border pt-8 text-xs leading-relaxed text-muted-foreground md:flex-row md:justify-between md:gap-12">
          <p className="max-w-3xl">
            FinGuard provides educational guidance based on common scam indicators. Results are not a
            guarantee that a message is safe or fraudulent and are not financial or legal advice. FinGuard
            is not affiliated with any bank, payment app, or government agency. Always verify payment
            requests through official channels.
          </p>
          <p className="shrink-0 font-mono">© {new Date().getFullYear()} FinGuard</p>
        </div>
      </div>
    </footer>
  )
}
