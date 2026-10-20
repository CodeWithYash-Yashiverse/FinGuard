const base =
  'inline-flex items-center justify-center gap-2 rounded-full font-medium transition-colors duration-200 outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50'

export const buttonStyles = {
  primary: `${base} bg-foreground text-background hover:bg-primary hover:text-primary-foreground`,
  accent: `${base} bg-primary text-primary-foreground hover:bg-primary/85`,
  ghost: `${base} border border-border text-foreground hover:border-foreground/40 hover:bg-white/[0.03]`,
  sizeMd: 'h-11 px-6 text-[15px]',
  sizeSm: 'h-9 px-4 text-sm',
}
