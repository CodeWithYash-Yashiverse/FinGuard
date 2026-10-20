'use client'

import { useRef, useState } from 'react'
import { ImageUp, Loader2 } from 'lucide-react'
import { buttonStyles } from '@/lib/button-styles'
import { cn } from '@/lib/utils'

const ACCEPTED = ['image/png', 'image/jpeg', 'image/webp']
const MAX_BYTES = 8 * 1024 * 1024

type OcrState =
  | { kind: 'idle' }
  | { kind: 'working'; progress: number }
  | { kind: 'done'; fileName: string }
  | { kind: 'error'; message: string }

export function ScreenshotUpload({
  onText,
  disabled,
}: {
  onText: (text: string) => void
  disabled?: boolean
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [state, setState] = useState<OcrState>({ kind: 'idle' })

  async function handleFile(file: File) {
    if (!ACCEPTED.includes(file.type)) {
      setState({ kind: 'error', message: 'Please choose a PNG, JPEG, or WebP image.' })
      return
    }
    if (file.size > MAX_BYTES) {
      setState({ kind: 'error', message: 'That image is larger than 8 MB. Try cropping the screenshot.' })
      return
    }

    setState({ kind: 'working', progress: 0 })
    try {
      const { createWorker } = await import('tesseract.js')
      const worker = await createWorker('eng', 1, {
        logger: (m) => {
          if (m.status === 'recognizing text') {
            setState({ kind: 'working', progress: Math.round(m.progress * 100) })
          }
        },
      })
      const {
        data: { text },
      } = await worker.recognize(file)
      await worker.terminate()

      const cleaned = text.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim()
      if (cleaned.length < 5) {
        setState({ kind: 'error', message: 'We could not read any text in that image. Try a sharper screenshot or paste the text.' })
        return
      }
      onText(cleaned)
      setState({ kind: 'done', fileName: file.name })
    } catch {
      setState({ kind: 'error', message: 'Text extraction failed. Please paste the message text instead.' })
    } finally {
      if (inputRef.current) inputRef.current.value = ''
    }
  }

  const working = state.kind === 'working'

  return (
    <div className="flex flex-col gap-2">
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED.join(',')}
        className="sr-only"
        tabIndex={-1}
        aria-hidden="true"
        onChange={(e) => {
          const file = e.target.files?.[0]
          if (file) void handleFile(file)
        }}
      />
      <button
        type="button"
        disabled={disabled || working}
        onClick={() => inputRef.current?.click()}
        className={cn(buttonStyles.ghost, buttonStyles.sizeSm)}
      >
        {working ? (
          <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" />
        ) : (
          <ImageUp className="size-4" aria-hidden="true" />
        )}
        {working ? `Reading screenshot… ${state.progress}%` : 'Extract from screenshot'}
      </button>
      <p role="status" aria-live="polite" className="font-mono text-xs">
        {state.kind === 'done' && (
          <span className="text-muted-foreground">
            Text extracted from {state.fileName}. Review it before analyzing.
          </span>
        )}
        {state.kind === 'error' && <span className="text-danger">{state.message}</span>}
      </p>
    </div>
  )
}
