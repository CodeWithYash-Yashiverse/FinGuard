import { NextResponse } from 'next/server'
import { analyzeMessage } from '@/lib/analysis/engine'
import {
  MESSAGE_MAX_LENGTH,
  MESSAGE_MIN_LENGTH,
  type AnalysisResult,
  type ApiErrorBody,
} from '@/lib/analysis/types'

export const runtime = 'nodejs'

const NO_STORE = { 'Cache-Control': 'no-store' }

function errorResponse(status: number, code: string, message: string) {
  return NextResponse.json<ApiErrorBody>({ error: { code, message } }, { status, headers: NO_STORE })
}

function isAnalysisResult(value: unknown): value is AnalysisResult {
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return (
    ['high_risk', 'suspicious', 'no_strong_signs'].includes(v.riskLevel as string) &&
    typeof v.summary === 'string' &&
    Array.isArray(v.signals) &&
    Array.isArray(v.nextSteps)
  )
}

async function analyzeRemotely(baseUrl: string, message: string): Promise<AnalysisResult> {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}/v1/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
    signal: AbortSignal.timeout(10_000),
    cache: 'no-store',
  })
  if (!res.ok) throw new Error(`Upstream responded with ${res.status}`)
  const data: unknown = await res.json()
  if (!isAnalysisResult(data)) throw new Error('Upstream returned an unexpected response shape')
  return {
    ...data,
    verification: data.verification ?? [],
    engine: { ...(data.engine ?? { name: 'FinGuard API', version: 'unknown' }), mode: 'remote' },
    analyzedAt: data.analyzedAt ?? new Date().toISOString(),
  }
}

export async function POST(request: Request) {
  let body: unknown
  try {
    body = await request.json()
  } catch {
    return errorResponse(400, 'invalid_json', 'The request body must be valid JSON.')
  }

  const message = (body as { message?: unknown })?.message
  if (typeof message !== 'string') {
    return errorResponse(400, 'invalid_message', 'Please provide the message text to analyze.')
  }
  const trimmed = message.trim()
  if (trimmed.length < MESSAGE_MIN_LENGTH) {
    return errorResponse(400, 'message_too_short', `Please paste at least ${MESSAGE_MIN_LENGTH} characters.`)
  }
  if (trimmed.length > MESSAGE_MAX_LENGTH) {
    return errorResponse(413, 'message_too_long', `Messages are limited to ${MESSAGE_MAX_LENGTH} characters.`)
  }

  const remoteUrl = process.env.FINGUARD_API_URL
  try {
    const result = remoteUrl ? await analyzeRemotely(remoteUrl, trimmed) : analyzeMessage(trimmed)
    return NextResponse.json(result, { headers: NO_STORE })
  } catch {
    return errorResponse(502, 'analysis_unavailable', 'The analysis service is unavailable right now. Please try again shortly.')
  }
}
