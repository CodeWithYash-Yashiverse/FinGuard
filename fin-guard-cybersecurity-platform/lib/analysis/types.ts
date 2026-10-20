export type RiskLevel = 'high_risk' | 'suspicious' | 'no_strong_signs'

export type Severity = 'high' | 'medium' | 'low'

export type SignalCategory =
  | 'link'
  | 'urgency'
  | 'credentials'
  | 'impersonation'
  | 'payment'
  | 'pattern'

export interface WarningSignal {
  id: string
  category: SignalCategory
  title: string
  severity: Severity
  explanation: string
  evidence: string[]
}

export interface AnalysisEngineInfo {
  name: string
  version: string
  mode: 'local' | 'remote'
}

export interface AnalysisResult {
  riskLevel: RiskLevel
  summary: string
  signals: WarningSignal[]
  nextSteps: string[]
  verification: string[]
  engine: AnalysisEngineInfo
  analyzedAt: string
}

export interface AnalyzeRequest {
  message: string
  source?: 'text' | 'ocr'
}

export interface ApiErrorBody {
  error: { code: string; message: string }
}

export const MESSAGE_MIN_LENGTH = 10
export const MESSAGE_MAX_LENGTH = 5000
