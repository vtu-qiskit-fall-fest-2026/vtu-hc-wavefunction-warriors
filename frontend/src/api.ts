/**
 * QuantumSafe API client.
 * Typed HTTP communication with the QuantumSafe FastAPI backend.
 */

export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8003'
).replace(/\/+$/, '')

export type Risk =
  | 'High risk'
  | 'Lower quantum risk'
  | 'Quantum-safe'
  | 'Invalid use case'
  | 'Unknown algorithm'

export interface ReferenceItem {
  standard_id: string
  title: string
  published: string
  url: string
}

export interface AlgorithmMetadata {
  id: string
  name: string
  aliases: string[]
  family: string
  cryptographic_role: string
  standardization_status: string
  status_label: string
  description: string
  supported_roles: string[]
  valid_use_cases: string[]
  base_risk: Risk
  prioritization_score: number
  score_rationale: string
  explanation: string
  quantum_threat: string
  alternative: string
  reference: ReferenceItem
}

export interface AssessRequest {
  algorithm: string
  use_case: string
  key_size?: number
}

export interface AssessResponse {
  algorithm: string
  algorithm_id?: string
  family?: string
  use_case: string
  cryptographic_role?: string
  is_valid_use_case: boolean
  risk_level: Risk
  reason: string
  quantum_threat: string
  recommendation: string
  prioritization_score: number
  score_rationale: string
  standardization_status?: string
  status_label?: string
  references: ReferenceItem[]
  reference_citation?: string
  caveats: string
}

export interface InventoryRow {
  asset_name: string
  algorithm: string
  use_case: string
  risk_level: Risk
  recommendation: string
  prioritization_score: number
  score_rationale?: string
  reason?: string
  quantum_threat?: string
  is_valid_use_case?: boolean
  standardization_status?: string
  status_label?: string
  reference_citation?: string
  environment?: string
  owner?: string
  criticality?: string
  description?: string
  row_index?: number
  // Legacy UI aliases
  asset: string
  useCase: string
  risk: Risk
  alternative: string
}

export interface InventorySummary {
  high_risk: number
  lower_risk: number
  quantum_safe: number
  invalid_use_case: number
  unknown_algorithm: number
  average_prioritization_score: number
  high_risk_percentage: number
  quantum_safe_percentage: number
}

export interface InventoryUploadResponse {
  status: 'success' | 'partial_success' | 'error'
  message: string
  total_assets: number
  summary: InventorySummary
  assets: InventoryRow[]
  errors: string[]
  warnings: string[]
}

export interface ReportSummary {
  total_assets: number
  risk_distribution: Record<string, number>
  risk_percentages: Record<string, number>
  algorithm_distribution: Record<string, number>
  criticality_distribution: Record<string, number>
  recommendations_count: number
  average_prioritization_score: number
  high_priority_assets: Array<{
    asset_name: string
    algorithm: string
    risk_level: string
    score: number
  }>
  migration_guidance: string[]
}

export interface ReportSummaryResponse {
  status: string
  total_assets: number
  summary: ReportSummary
}

export interface HealthResponse {
  status: string
  version?: string
  service?: string
  backend_available?: boolean
  active_inventory_count?: number
  note?: string
}

async function handleHttpError(
  response: Response,
  defaultMessage: string,
): Promise<never> {
  let detail = ''
  try {
    const body = await response.json()
    if (typeof body.detail === 'string') {
      detail = body.detail
    } else if (Array.isArray(body.detail)) {
      detail = body.detail.map((item: any) => item.msg || JSON.stringify(item)).join(', ')
    } else if (typeof body.message === 'string') {
      detail = body.message
    }
  } catch {
    // The response may not contain JSON.
  }

  throw new Error(
    detail
      ? `${defaultMessage}: ${detail}`
      : `${defaultMessage} (HTTP ${response.status})`,
  )
}

async function requestJson<T>(url: string, init?: RequestInit, label = 'Request failed'): Promise<T> {
  let response: Response
  try {
    response = await fetch(url, init)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Network error'
    throw new Error(`${label}: ${message}`)
  }

  if (!response.ok) {
    return handleHttpError(response, label)
  }

  return response.json() as Promise<T>
}

/** Check whether the FastAPI backend is reachable. */
export async function checkBackendHealth(): Promise<HealthResponse> {
  return requestJson<HealthResponse>(
    `${API_BASE_URL}/api/health`,
    undefined,
    `Unable to connect to QuantumSafe backend at ${API_BASE_URL}`,
  )
}

const algorithmMetadata: Record<string, {
  family: string
  description: string
  useCases: string[]
  risk: Risk
  alternative: string
  standard: string
}> = {
  RSA: {
    family: 'Public-key cryptography',
    description: 'Widely used for key establishment and digital signatures.',
    useCases: ['key_establishment', 'digital_signatures'],
    risk: 'High risk',
    alternative: 'ML-KEM for key establishment; ML-DSA or SLH-DSA for signatures',
    standard: 'NIST PQC transition guidance',
  },
  ECDH: {
    family: 'Elliptic-curve key exchange',
    description: 'Establishes shared secrets using elliptic curves.',
    useCases: ['key_establishment'],
    risk: 'High risk',
    alternative: 'ML-KEM (NIST FIPS 203)',
    standard: 'NIST FIPS 203',
  },
  ECDSA: {
    family: 'Elliptic-curve signatures',
    description: 'Creates digital signatures using elliptic curves.',
    useCases: ['digital_signatures'],
    risk: 'High risk',
    alternative: 'ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)',
    standard: 'NIST FIPS 204 / FIPS 205',
  },
  'AES-128': {
    family: 'Symmetric encryption',
    description: 'Symmetric encryption with a 128-bit key.',
    useCases: ['symmetric_encryption'],
    risk: 'Lower quantum risk',
    alternative: 'Consider AES-256 where appropriate and follow key-management guidance',
    standard: 'NIST SP 800-57',
  },
  'AES-256': {
    family: 'Symmetric encryption',
    description: 'Symmetric encryption with a 256-bit key.',
    useCases: ['symmetric_encryption'],
    risk: 'Lower quantum risk',
    alternative: 'Continue using sound implementation and key management',
    standard: 'NIST SP 800-57',
  },
  'ML-KEM': {
    family: 'Post-quantum key establishment',
    description: 'Standardized post-quantum key-encapsulation mechanism.',
    useCases: ['key_establishment'],
    risk: 'Quantum-safe',
    alternative: 'No replacement indicated; validate implementation and parameters',
    standard: 'NIST FIPS 203',
  },
  'ML-DSA': {
    family: 'Post-quantum signatures',
    description: 'Standardized post-quantum digital signature algorithm.',
    useCases: ['digital_signatures'],
    risk: 'Quantum-safe',
    alternative: 'No replacement indicated; validate implementation and parameters',
    standard: 'NIST FIPS 204',
  },
  'SLH-DSA': {
    family: 'Post-quantum signatures',
    description: 'Standardized stateless hash-based digital signatures.',
    useCases: ['digital_signatures'],
    risk: 'Quantum-safe',
    alternative: 'No replacement indicated; evaluate signature size and performance',
    standard: 'NIST FIPS 205',
  },
}

/**
 * The current backend's /api/algorithms response contains an array of names.
 * Convert those names into the metadata shape expected by the React UI.
 */
export async function fetchAlgorithms(): Promise<AlgorithmMetadata[]> {
  const data = await requestJson<{ algorithms?: unknown[] }>(
    `${API_BASE_URL}/api/algorithms`,
    undefined,
    'Failed to fetch supported algorithms',
  )

  const names = Array.isArray(data.algorithms)
    ? data.algorithms.filter((name): name is string => typeof name === 'string')
    : []

  return names.map((name) => {
    const meta = algorithmMetadata[name] ?? {
      family: 'Cryptographic algorithm',
      description: name,
      useCases: [],
      risk: 'Unknown algorithm' as Risk,
      alternative: 'Review the algorithm and its intended use case.',
      standard: '',
    }

    const reference: ReferenceItem = {
      standard_id: meta.standard,
      title: meta.standard,
      published: '',
      url: '',
    }

    return {
      id: name,
      name,
      aliases: [],
      family: meta.family,
      cryptographic_role: meta.family,
      standardization_status: name.startsWith('ML-') || name === 'SLH-DSA'
        ? 'Standardized post-quantum algorithm'
        : 'Classical / symmetric algorithm',
      status_label: name.startsWith('ML-') || name === 'SLH-DSA'
        ? 'Post-quantum'
        : 'Established algorithm',
      description: meta.description,
      supported_roles: meta.useCases,
      valid_use_cases: meta.useCases,
      base_risk: meta.risk,
      prioritization_score: 0,
      score_rationale: '',
      explanation: meta.description,
      quantum_threat: '',
      alternative: meta.alternative,
      reference,
    }
  })
}

/** Run a security assessment through POST /api/assess. */
export async function assessAlgorithmApi(payload: AssessRequest): Promise<AssessResponse> {
  return requestJson<AssessResponse>(
    `${API_BASE_URL}/api/assess`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
    'Algorithm assessment failed',
  )
}

/** Alias for compatibility with code using the shorter function name. */
export const assessAlgorithm = assessAlgorithmApi

/** Upload and assess a CSV inventory through multipart/form-data. */
export async function uploadInventoryCsvApi(file: File): Promise<InventoryUploadResponse> {
  const formData = new FormData()
  formData.append('file', file)

  const raw = await requestJson<any>(
    `${API_BASE_URL}/api/inventory/upload`,
    { method: 'POST', body: formData },
    'CSV inventory upload failed',
  )

  const assets: InventoryRow[] = (Array.isArray(raw.assets) ? raw.assets : []).map((row: any) => ({
    ...row,
    asset_name: row.asset_name ?? row.asset ?? '',
    asset: row.asset ?? row.asset_name ?? '',
    use_case: row.use_case ?? row.useCase ?? '',
    useCase: row.useCase ?? row.use_case ?? '',
    risk_level: row.risk_level ?? row.risk ?? 'Unknown algorithm',
    risk: row.risk ?? row.risk_level ?? 'Unknown algorithm',
    recommendation: row.recommendation ?? row.alternative ?? '',
    alternative: row.alternative ?? row.recommendation ?? '',
    prioritization_score: row.prioritization_score ?? 0,
  }))

  return {
    status: raw.status ?? 'success',
    message: raw.message ?? `Processed ${assets.length} asset(s).`,
    total_assets: raw.total_assets ?? assets.length,
    summary: raw.summary ?? {
      high_risk: 0,
      lower_risk: 0,
      quantum_safe: 0,
      invalid_use_case: 0,
      unknown_algorithm: 0,
      average_prioritization_score: 0,
      high_risk_percentage: 0,
      quantum_safe_percentage: 0,
    },
    assets,
    errors: Array.isArray(raw.errors) ? raw.errors : [],
    warnings: Array.isArray(raw.warnings) ? raw.warnings : [],
  }
}

/** Fetch report summary. */
export async function fetchReportSummaryApi(): Promise<ReportSummaryResponse> {
  const raw = await requestJson<any>(
    `${API_BASE_URL}/api/report/summary`,
    undefined,
    'Failed to load report summary',
  )

  // Support both { summary: {...} } and a summary object returned directly.
  const summary = raw.summary ?? raw
  return {
    status: raw.status ?? 'success',
    total_assets: raw.total_assets ?? summary.total_assets ?? 0,
    summary: {
      total_assets: summary.total_assets ?? raw.total_assets ?? 0,
      risk_distribution: summary.risk_distribution ?? {},
      risk_percentages: summary.risk_percentages ?? {},
      algorithm_distribution: summary.algorithm_distribution ?? {},
      criticality_distribution: summary.criticality_distribution ?? {},
      recommendations_count: summary.recommendations_count ?? 0,
      average_prioritization_score: summary.average_prioritization_score ?? 0,
      high_priority_assets: summary.high_priority_assets ?? [],
      migration_guidance: summary.migration_guidance ?? [],
    },
  }
}

/** Download the CSV assessment report. */
export async function downloadReportCsvApi(): Promise<void> {
  const url = `${API_BASE_URL}/api/report/export`
  const response = await fetch(url)

  if (!response.ok) {
    return handleHttpError(response, 'Failed to download report')
  }

  let filename = 'quantumsafe-assessment.csv'
  const disposition = response.headers.get('content-disposition')
  const match = disposition?.match(/filename="?([^";]+)"?/i)
  if (match?.[1]) filename = match[1]

  const blob = await response.blob()
  const blobUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = blobUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(blobUrl)
}
