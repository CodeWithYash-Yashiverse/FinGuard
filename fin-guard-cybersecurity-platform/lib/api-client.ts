import type { AnalysisResult, AnalyzeRequest, ApiErrorBody } from './analysis/types'

export class AnalysisError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message)
    this.name = 'AnalysisError'
  }
}

export async function analyzeMessage(request: AnalyzeRequest): Promise<AnalysisResult> {
  let res: Response
  try {
    res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
      cache: 'no-store',
    })
  } catch {
    throw new AnalysisError('We could not reach the analysis service. Check your connection and try again.', 'network_error')
  }

  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as ApiErrorBody | null
    throw new AnalysisError(
      body?.error?.message ?? 'Something went wrong while analyzing the message.',
      body?.error?.code ?? 'unknown_error',
    )
  }
  return (await res.json()) as AnalysisResult
}
