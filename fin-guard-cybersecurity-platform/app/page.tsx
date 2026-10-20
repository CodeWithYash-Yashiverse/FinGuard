import { SiteHeader } from '@/components/layout/site-header'
import { SiteFooter } from '@/components/layout/site-footer'
import { Hero } from '@/components/sections/hero'
import { CheckerSection } from '@/components/checker/checker-section'
import { HowItWorks } from '@/components/sections/how-it-works'
import { WhatWeCheck } from '@/components/sections/what-we-check'
import { Privacy } from '@/components/sections/privacy'
import { Safety } from '@/components/sections/safety'

export default function Page() {
  return (
    <>
      <SiteHeader />
      <main>
        <Hero />
        <CheckerSection />
        <HowItWorks />
        <WhatWeCheck />
        <Privacy />
        <Safety />
      </main>
      <SiteFooter />
    </>
  )
}
