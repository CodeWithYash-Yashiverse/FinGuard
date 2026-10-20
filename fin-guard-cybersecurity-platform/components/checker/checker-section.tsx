'use client'

import { useRef, useState } from 'react'
import { AlertCircle, ArrowRight, Loader2, LockKeyhole } from 'lucide-react'
import { analyzeMessage, AnalysisError } from '@/lib/api-client'
import {
  MESSAGE_MAX_LENGTH,
  MESSAGE_MIN_LENGTH,
  type AnalysisResult,
} from '@/lib/analysis/types'
import { buttonStyles } from '@/lib/button-styles'
import { cn } from '@/lib/utils'
import { ScreenshotUpload } from './screenshot-upload'
import { AnalysisResults } from '@/components/results/analysis-results'
import { EXAMPLE_MESSAGES } from './example-messages'

type Status =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'success'; result: AnalysisResult }
  | { kind: 'error'; message: string }

export function CheckerSection() {
  const [message, setMessage] = useState('')
  const [source, setSource] = useState<'text' | 'ocr'>('text')
  const [status, setStatus] = useState<Status>({ kind: 'idle' })
  const [validation, setValidation] = useState<string | null>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const resultsRef = useRef<HTMLDivElement>(null)

  const loading = status.kind === 'loading'
  const length = message.trim().length

  async function submit() {
    if (length < MESSAGE_MIN_LENGTH) {
      setValidation(
        length === 0
          ? 'Paste a message to analyze.'
          : `Please include at least ${MESSAGE_MIN_LENGTH} characters so there is enough to analyze.`,
      )
      textareaRef.current?.focus()
      return
    }
    setValidation(null)
    setStatus({ kind: 'loading' })
    try {
      const result = await analyzeMessage({ message, source })
      setStatus({ kind: 'success', result })
      requestAnimationFrame(() => {
        resultsRef.current?.scrollIntoView({ block: 'start' })
        resultsRef.current?.focus({ preventScroll: true })
      })
    } catch (err) {
      setStatus({
        kind: 'error',
        message: err instanceof AnalysisError ? err.message : 'Something went wrong. Please try again.',
      })
    }
  }

  function reset() {
    setMessage('')
    setSource('text')
    setStatus({ kind: 'idle' })
    setValidation(null)
    document.getElementById('checker')?.scrollIntoView({ block: 'start' })
    requestAnimationFrame(() => textareaRef.current?.focus({ preventScroll: true }))
  }

  return (
    <section id="checker" aria-labelledby="checker-title" className="relative border-b border-border bg-surface/40">
      <div className="mx-auto grid max-w-7xl gap-12 px-5 py-20 md:px-8 md:py-28 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-20">
        <div className="flex flex-col gap-6">
          <p className="font-mono text-xs tracking-[0.18em] text-primary uppercase">Message check</p>
          <h2 id="checker-title" className="text-4xl leading-tight font-light tracking-[-0.03em] text-balance md:text-5xl">
            Paste the message. See what stands out.
          </h2>
          <p className="max-w-md leading-relaxed text-muted-foreground text-pretty">
            Copy a suspicious SMS, UPI collect request, WhatsApp message, or payment email. FinGuard
            highlights the warning signs it finds and explains each one.
          </p>

          <div className="mt-2 flex gap-3 rounded-xl border border-border bg-background/60 p-4">
            <LockKeyhole className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
            <p className="text-sm leading-relaxed text-muted-foreground">
              <span className="text-foreground">How your text is handled:</span> it is sent once for
              analysis, never saved to a database or your browser, and discarded after the result is
              returned. Screenshots are read on your device and never uploaded. Remove account numbers
              before pasting, and never enter your UPI PIN, OTP, or passwords here.
            </p>
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void submit()
            }}
            className="rounded-2xl border border-border bg-background shadow-[0_0_0_1px_rgb(255_255_255/0.02),0_30px_80px_-40px_rgb(67_217_189/0.15)]"
            aria-busy={loading}
          >
            <div className="flex items-center justify-between border-b border-border px-5 py-3">
              <label htmlFor="message" className="font-mono text-xs tracking-wider text-muted-foreground uppercase">
                Suspicious message
              </label>
              <span className="font-mono text-xs text-muted-foreground tabular-nums" aria-live="polite">
                {message.length}/{MESSAGE_MAX_LENGTH}
              </span>
            </div>

            <textarea
              ref={textareaRef}
              id="message"
              name="message"
              value={message}
              maxLength={MESSAGE_MAX_LENGTH}
              disabled={loading}
              onChange={(e) => {
                setMessage(e.target.value)
                if (validation) setValidation(null)
                if (e.target.value.length === 0) setSource('text')
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                  if (e.nativeEvent.isComposing || e.keyCode === 229) return
                  e.preventDefault()
                  void submit()
                }
              }}
              rows={9}
              placeholder="e.g. Dear customer, your SBI account will be blocked today. Update KYC at…"
              aria-invalid={validation ? true : undefined}
              aria-describedby={validation ? 'message-error' : 'message-hint'}
              className="block w-full resize-y bg-transparent px-5 py-4 text-[15px] leading-relaxed text-foreground placeholder:text-muted-foreground/60 focus:outline-none disabled:opacity-60"
            />

            <div className="flex flex-col gap-4 border-t border-border px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
              <ScreenshotUpload
                disabled={loading}
                onText={(text) => {
                  setMessage(text.slice(0, MESSAGE_MAX_LENGTH))
                  setSource('ocr')
                  setValidation(null)
                }}
              />
              <button
                type="submit"
                disabled={loading}
                className={cn(buttonStyles.accent, buttonStyles.sizeMd, 'group shrink-0')}
              >
                {loading ? (
                  <>
                    <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" />
                    Analyzing…
                  </>
                ) : (
                  <>
                    Analyze Message
                    <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
                  </>
                )}
              </button>
            </div>
          </form>

          {validation ? (
            <p id="message-error" role="alert" className="flex items-center gap-2 text-sm text-danger">
              <AlertCircle className="size-4" aria-hidden="true" />
              {validation}
            </p>
          ) : (
            <p id="message-hint" className="font-mono text-xs text-muted-foreground">
              Tip: press Ctrl/⌘ + Enter to analyze.
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-muted-foreground">Try an example message:</span>
            {EXAMPLE_MESSAGES.map((ex) => (
              <button
                key={ex.label}
                type="button"
                disabled={loading}
                onClick={() => {
                  setMessage(ex.text)
                  setSource('text')
                  setValidation(null)
                  textareaRef.current?.focus()
                }}
                className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground transition-colors hover:border-foreground/30 hover:text-foreground disabled:opacity-50"
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-5 md:px-8">
        <div ref={resultsRef} tabIndex={-1} className="scroll-mt-24 outline-none" aria-live="polite">
          {status.kind === 'idle' && <EmptyResults />}
          {status.kind === 'loading' && <LoadingResults />}
          {status.kind === 'error' && (
            <div role="alert" className="mb-20 flex flex-col gap-4 rounded-2xl border border-danger/40 bg-danger/5 p-6 sm:flex-row sm:items-center sm:justify-between md:mb-28">
              <div className="flex items-start gap-3">
                <AlertCircle className="mt-0.5 size-5 shrink-0 text-danger" aria-hidden="true" />
                <div>
                  <p className="font-medium text-foreground">Analysis could not be completed</p>
                  <p className="mt-1 text-sm text-muted-foreground">{status.message}</p>
                </div>
              </div>
              <button type="button" onClick={() => void submit()} className={cn(buttonStyles.ghost, buttonStyles.sizeSm)}>
                Try again
              </button>
            </div>
          )}
          {status.kind === 'success' && <AnalysisResults result={status.result} onReset={reset} />}
        </div>
      </div>
    </section>
  )
}

function EmptyResults() {
  return (
    <div className="mb-20 rounded-2xl border border-dashed border-border px-6 py-10 text-center md:mb-28">
      <p className="font-mono text-xs tracking-wider text-muted-foreground uppercase">No message analyzed yet</p>
      <p className="mx-auto mt-2 max-w-md text-sm text-muted-foreground">
        Your results will appear here: an overall assessment, each warning sign with the exact text that
        triggered it, and what to do next.
      </p>
    </div>
  )
}

function LoadingResults() {
  return (
    <div className="mb-20 rounded-2xl border border-border p-6 md:mb-28 md:p-10" role="status">
      <span className="sr-only">Analyzing message</span>
      <div className="flex animate-pulse flex-col gap-4 motion-reduce:animate-none">
        <div className="h-3 w-32 rounded bg-white/5" />
        <div className="h-8 w-64 rounded bg-white/5" />
        <div className="h-3 w-full max-w-xl rounded bg-white/5" />
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <div className="h-28 rounded-xl bg-white/[0.03]" />
          <div className="h-28 rounded-xl bg-white/[0.03]" />
        </div>
      </div>
    </div>
  )
}
