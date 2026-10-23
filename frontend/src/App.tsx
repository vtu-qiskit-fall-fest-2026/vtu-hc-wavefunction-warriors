import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import * as api from './api'
import type {
  AssessResponse,
  AlgorithmMetadata,
  InventoryRow,
  ReportSummary,
  Risk,
} from './api'

// Resolve the assessment function using either supported export name.
// This avoids a module-load crash if api.ts exports assessAlgorithm instead.
const apiExports = api as typeof api & {
  API_BASE_URL?: string
  assessAlgorithmApi?: (payload: { algorithm: string; use_case: string }) => Promise<AssessResponse>
  assessAlgorithm?: (payload: { algorithm: string; use_case: string }) => Promise<AssessResponse>
}
const {
  checkBackendHealth,
  fetchAlgorithms,
  uploadInventoryCsvApi,
  fetchReportSummaryApi,
  downloadReportCsvApi,
} = apiExports
const API_BASE_URL = apiExports.API_BASE_URL || 'http://127.0.0.1:8003'
const assessAlgorithmApi =
  apiExports.assessAlgorithmApi ?? apiExports.assessAlgorithm

type Page = 'dashboard' | 'checker' | 'inventory' | 'reports' | 'roadmap' | 'about'

type FallbackAlgorithm = {
  name: string
  family: string
  description: string
  useCases: string[]
  risk: Risk
  explanation: string
  attack: string
  alternative: string
  reference: string
}

const defaultAlgorithms: FallbackAlgorithm[] = [
  {
    name: 'RSA',
    family: 'Public-key cryptography',
    description: 'Widely used for key exchange and digital signatures.',
    useCases: ['TLS key exchange', 'Digital signatures', 'Certificate authentication', 'Data encryption'],
    risk: 'High risk',
    explanation: 'RSA relies on integer factorization, which a sufficiently capable quantum computer could solve efficiently.',
    attack: 'Shor’s algorithm can factor the large composite numbers at the core of RSA security, breaking both encryption and signatures.',
    alternative: 'ML-KEM for key establishment; ML-DSA or SLH-DSA for signatures',
    reference: 'NIST IR 8547 · Transition to Post-Quantum Cryptography Standards',
  },
  {
    name: 'ECDH',
    family: 'Elliptic-curve key exchange',
    description: 'Establishes shared secrets using elliptic curves.',
    useCases: ['TLS key exchange', 'Secure messaging', 'VPN key exchange'],
    risk: 'High risk',
    explanation: 'ECDH depends on the elliptic-curve discrete logarithm problem and is vulnerable to a cryptographically relevant quantum computer.',
    attack: 'Shor’s algorithm can recover elliptic-curve private keys from public keys, compromising established sessions.',
    alternative: 'ML-KEM (NIST FIPS 203)',
    reference: 'NIST FIPS 203 · Module-Lattice-Based Key-Encapsulation Mechanism',
  },
  {
    name: 'ECDSA',
    family: 'Elliptic-curve signatures',
    description: 'Creates compact digital signatures using elliptic curves.',
    useCases: ['Code signing', 'Certificate authentication', 'Document signing', 'Transaction signing'],
    risk: 'High risk',
    explanation: 'ECDSA depends on the elliptic-curve discrete logarithm problem, which is not quantum-resistant.',
    attack: 'Shor’s algorithm can derive a signing key from its public key, enabling forged signatures.',
    alternative: 'ML-DSA (NIST FIPS 204) or SLH-DSA (NIST FIPS 205)',
    reference: 'NIST FIPS 204 · Module-Lattice-Based Digital Signature Standard',
  },
  {
    name: 'AES',
    family: 'Symmetric encryption',
    description: 'A modern symmetric cipher used to protect data at rest and in transit.',
    useCases: ['Data at rest', 'Application encryption', 'Backup encryption', 'Secure transport'],
    risk: 'Lower quantum risk',
    explanation: 'AES is not broken by Shor’s algorithm. Grover’s algorithm provides a quadratic search speedup, reducing its effective security margin.',
    attack: 'Grover’s algorithm could accelerate brute-force key search, but doubling key size substantially mitigates this risk.',
    alternative: 'AES-256 with sound key management',
    reference: 'NIST SP 800-57 Part 1 · Recommendation for Key Management',
  },
  {
    name: 'ML-KEM',
    family: 'Post-quantum key establishment',
    description: 'A standardized lattice-based key encapsulation mechanism.',
    useCases: ['TLS key establishment', 'Hybrid key exchange', 'Secure messaging'],
    risk: 'Quantum-safe',
    explanation: 'ML-KEM is designed to resist attacks by both classical and quantum computers.',
    attack: 'No practical quantum attack is known against its underlying module-lattice problem when implemented correctly.',
    alternative: 'No replacement required; follow implementation and parameter guidance',
    reference: 'NIST FIPS 203 · ML-KEM',
  },
  {
    name: 'ML-DSA',
    family: 'Post-quantum signatures',
    description: 'A standardized lattice-based digital signature algorithm.',
    useCases: ['Code signing', 'Document signing', 'Certificate authentication'],
    risk: 'Quantum-safe',
    explanation: 'ML-DSA is designed for digital signatures in a post-quantum security environment.',
    attack: 'No practical quantum attack is known against its underlying module-lattice assumptions when implemented correctly.',
    alternative: 'No replacement required; validate parameter set and integration',
    reference: 'NIST FIPS 204 · ML-DSA',
  },
  {
    name: 'SLH-DSA',
    family: 'Post-quantum signatures',
    description: 'A stateless hash-based signature scheme with conservative assumptions.',
    useCases: ['Firmware signing', 'Long-lived signatures', 'Root-of-trust signing'],
    risk: 'Quantum-safe',
    explanation: 'SLH-DSA is based on the security of cryptographic hash functions and is designed for post-quantum use.',
    attack: 'Quantum search affects hash security margins, which are accounted for in the standardized parameter sets.',
    alternative: 'No replacement required; assess signature size and performance needs',
    reference: 'NIST FIPS 205 · SLH-DSA',
  },
]

const navItems: { id: Page; label: string; icon: IconName }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid' },
  { id: 'checker', label: 'Security Checker', icon: 'shield' },
  { id: 'inventory', label: 'Asset Inventory', icon: 'database' },
  { id: 'reports', label: 'Reports', icon: 'chart' },
  { id: 'roadmap', label: 'Migration Roadmap', icon: 'route' },
  { id: 'about', label: 'About', icon: 'info' },
]

const roadmapSteps = [
  ['Discover cryptographic assets', 'Build a complete inventory across applications, infrastructure, and data flows.'],
  ['Identify vulnerable algorithms', 'Flag public-key algorithms exposed to future quantum attacks.'],
  ['Prioritize high-risk assets', 'Consider data lifetime, exposure, criticality, and migration complexity.'],
  ['Select quantum-safe alternatives', 'Map each cryptographic use case to an appropriate standardized alternative.'],
  ['Test compatibility & performance', 'Evaluate integrations, key sizes, latency, and operational impact.'],
  ['Plan migration & validate', 'Roll out in controlled phases and verify deployment outcomes.'],
]

type IconName =
  | 'grid' | 'shield' | 'database' | 'chart' | 'route' | 'info' | 'spark'
  | 'arrow' | 'upload' | 'download' | 'check' | 'alert' | 'menu' | 'close'
  | 'chevron' | 'file' | 'lock' | 'book' | 'clock' | 'spinner'

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  const paths: Record<IconName, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /></>,
    shield: <><path d="M12 3 4.8 6v5.3c0 4.5 2.9 8.4 7.2 9.7 4.3-1.3 7.2-5.2 7.2-9.7V6L12 3Z" /><path d="m9.2 12 1.8 1.8 3.9-4.1" /></>,
    database: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></>,
    chart: <><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" /></>,
    route: <><circle cx="6" r="2.5" cy="18" /><circle cx="18" r="2.5" cy="6" /><path d="M8.5 18h2.2a3 3 0 0 0 3-3V9a3 3 0 0 1 3-3" /></>,
    info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>,
    spark: <path d="m12 2 1.4 5.2a4.8 4.8 0 0 0 3.4 3.4L22 12l-5.2 1.4a4.8 4.8 0 0 0-3.4 3.4L12 22l-1.4-5.2a4.8 4.8 0 0 0-3.4-3.4L2 12l5.2-1.4a4.8 4.8 0 0 0 3.4-3.4L12 2Z" />,
    arrow: <><path d="M5 12h14M14 7l5 5-5 5" /></>,
    upload: <><path d="M12 16V4M7 9l5-5 5 5M4 20h16" /></>,
    download: <><path d="M12 4v12M7 11l5 5 5-5M4 20h16" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M10.3 3.7 2.4 18a2 2 0 0 0 1.8 3h15.6a2 2 0 0 0 1.8-3L13.7 3.7a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4M12 17h.01" /></>,
    menu: <path d="M4 7h16M4 12h16M4 17h16" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    chevron: <path d="m9 18 6-6-6-6" />,
    file: <><path d="M6 2h8l4 4v16H6z" /><path d="M14 2v5h5M9 13h6M9 17h6" /></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="3" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>,
    book: <><path d="M4 5a3 3 0 0 1 3-3h5v18H7a3 3 0 0 0-3 2V5Z" /><path d="M20 5a3 3 0 0 0-3-3h-5v18h5a3 3 0 0 1 3 2V5Z" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    spinner: <path d="M21 12a9 9 0 1 1-6.219-8.56" className="animate-spin" />,
  }
  return <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>
}

function Text({ as: Tag = 'p', className = '', children }: { as?: 'h1' | 'h2' | 'h3' | 'p' | 'span'; className?: string; children: ReactNode }) {
  return <Tag className={className}>{children}</Tag>
}

function Button({ children, onClick, variant = 'primary', icon, disabled = false, type = 'button', loading = false }: {
  children: ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost'
  icon?: IconName
  disabled?: boolean
  type?: 'button' | 'submit'
  loading?: boolean
}) {
  return <button className={`button button--${variant} ${loading ? 'button--loading' : ''}`} onClick={onClick} disabled={disabled || loading} type={type}>
    {loading ? <Icon name="spinner" /> : (icon && <Icon name={icon} />)}
    {children}
  </button>
}

function Card({ children, className = '', glow }: { children: ReactNode; className?: string; glow?: 'violet' | 'teal' }) {
  return <div className={`glass-card ${glow ? `glow-${glow}` : ''} ${className}`}>{children}</div>
}


function RiskPill({ risk }: { risk?: Risk | string | null }) {
  const safeRisk = typeof risk === 'string' && risk.trim()
    ? risk.trim()
    : 'Unknown algorithm'

  const slug = safeRisk
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')

  return (
    <span className={`risk-pill risk-${slug}`}>
      <span className="risk-dot" />
      {safeRisk}
    </span>
  )
}

function SelectField({ label, value, onChange, options, hint, disabled }: {
  label: string
  value: string
  onChange: (value: string) => void
  options: string[]
  hint?: string
  disabled?: boolean
}) {
  return <label className="field">
    <span className="field-label">{label}</span>
    <span className="select-wrap">
      <select value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled}>
        {options.map((option) => <option key={option}>{option}</option>)}
      </select>
      <Icon name="chevron" size={16} />
    </span>
    {hint && <span className="field-hint">{hint}</span>}
  </label>
}

function Logo() {
  return <div className="brand">
    <div className="brand-mark"><span className="orbit orbit-a" /><span className="orbit orbit-b" /><span className="core" /></div>
    <div><Text as="span" className="brand-name">QuantumSafe</Text><Text as="span" className="brand-tagline">SECURITY CHECKER</Text></div>
  </div>
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <header className="page-header">
    <div>
      <Text as="span" className="eyebrow">{eyebrow}</Text>
      <Text as="h1" className="page-title">{title}</Text>
      <Text className="page-description">{description}</Text>
    </div>
    {action}
  </header>
}

function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [menuOpen, setMenuOpen] = useState(false)
  const [algorithmsList, setAlgorithmsList] = useState<Array<{ name: string; family: string; description: string; useCases: string[]; risk: Risk }>>(defaultAlgorithms)
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('RSA')
  const [useCase, setUseCase] = useState(defaultAlgorithms[0].useCases[0])
  const [assessment, setAssessment] = useState<AssessResponse | null>(null)
  const [isAssessing, setIsAssessing] = useState(false)
  const [assessError, setAssessError] = useState<string | null>(null)

  const [inventory, setInventory] = useState<InventoryRow[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadMessage, setUploadMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  const [reportSummary, setReportSummary] = useState<ReportSummary | null>(null)
  const [summaryLoading, setSummaryLoading] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)

  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)

  // Find active algorithm metadata
  const currentAlgo = algorithmsList.find((item) => item.name === selectedAlgorithm) || algorithmsList[0]

  // Probe backend on mount
  const checkHealth = async () => {
    try {
      await checkBackendHealth()
      setBackendOnline(true)
      // Load rich algorithm metadata from FastAPI
      const backendAlgos = await fetchAlgorithms()
      if (backendAlgos && backendAlgos.length > 0) {
        setAlgorithmsList(backendAlgos.map(a => ({
          name: a.name,
          family: a.family,
          description: a.description,
          useCases: a.valid_use_cases,
          risk: a.base_risk,
        })))
      }
    } catch {
      setBackendOnline(false)
    }
  }

  useEffect(() => {
    checkHealth()
  }, [])

  // Sync use case when algorithm changes
  useEffect(() => {
    if (currentAlgo && currentAlgo.useCases.length > 0) {
      setUseCase(currentAlgo.useCases[0])
    }
    setAssessment(null)
    setAssessError(null)
  }, [selectedAlgorithm])

  // Fetch report summary when navigating to reports
  useEffect(() => {
    if (page === 'reports' && inventory.length > 0) {
      setSummaryLoading(true)
      fetchReportSummaryApi()
        .then((res) => {
          if (res.summary) {
            setReportSummary(res.summary)
          }
        })
        .catch(() => {
          // Fall back gracefully to client inventory counts
        })
        .finally(() => setSummaryLoading(false))
    }
  }, [page, inventory.length])

  const navigate = (target: Page) => {
    setPage(target)
    setMenuOpen(false)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  // Security Assessment via FastAPI
  const handleAssess = async () => {
    setIsAssessing(true)
    setAssessError(null)
    try {
      if (!assessAlgorithmApi) {
        throw new Error(
          'The assessment function is missing from src/api.ts. Export assessAlgorithmApi or assessAlgorithm from that file.'
        )
      }
      const response = await assessAlgorithmApi({
        algorithm: selectedAlgorithm,
        use_case: useCase,
      })
      setAssessment(response)
      setBackendOnline(true)
    } catch (err: any) {
      setAssessError(err.message || 'Assessment failed. Please verify that the FastAPI backend is running.')
      setBackendOnline(false)
    } finally {
      setIsAssessing(false)
    }
  }

  // CSV Inventory Upload via FastAPI
  const handleCsvUpload = async (file?: File) => {
    if (!file) return
    setIsUploading(true)
    setUploadMessage(null)
    try {
      const response = await uploadInventoryCsvApi(file)
      setInventory(response.assets)
      setBackendOnline(true)

      const warningText = response.errors.length
        ? ` Note: ${response.errors.length} issue(s) detected (${response.errors.slice(0, 2).join('; ')}).`
        : ''

      setUploadMessage({
        type: response.status === 'error' ? 'error' : 'success',
        text: `${response.message}${warningText}`,
      })
    } catch (err: any) {
      setUploadMessage({
        type: 'error',
        text: err.message || 'Failed to upload inventory. Please check backend connection.',
      })
      setBackendOnline(false)
    } finally {
      setIsUploading(false)
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  // CSV Report Download via FastAPI
  const handleDownloadReport = async () => {
    if (!inventory.length) return
    setIsDownloading(true)
    try {
      await downloadReportCsvApi()
      setBackendOnline(true)
    } catch (err: any) {
      alert(`Download failed: ${err.message || 'Check backend connection'}`)
      setBackendOnline(false)
    } finally {
      setIsDownloading(false)
    }
  }

  return <div className="app-shell">
    <div className="ambient ambient-one" />
    <div className="ambient ambient-two" />
    <button className="mobile-menu" onClick={() => setMenuOpen(!menuOpen)} aria-label="Toggle navigation"><Icon name={menuOpen ? 'close' : 'menu'} /></button>
    <aside className={`sidebar ${menuOpen ? 'sidebar--open' : ''}`}>
      <Logo />
      <nav className="nav-list" aria-label="Main navigation">
        <Text as="span" className="nav-label">WORKSPACE</Text>
        {navItems.map((item) => <button key={item.id} className={`nav-item ${page === item.id ? 'nav-item--active' : ''}`} onClick={() => navigate(item.id)}>
          <Icon name={item.icon} /><span>{item.label}</span>{page === item.id && <span className="active-indicator" />}
        </button>)}
      </nav>
      <Card className="sidebar-note">
        <div className="note-icon"><Icon name="book" /></div>
        <Text as="h3">Educational tool</Text>
        <Text>Guidance is informational and aligned with finalized NIST FIPS 203/204/205 standards.</Text>
      </Card>
      <div className="sidebar-footer">
        <button
          className="api-badge"
          onClick={checkHealth}
          title="Click to re-check FastAPI backend health"
          style={{ background: 'transparent', border: 0, padding: 0 }}
        >
          <span className={`status-dot ${backendOnline === true ? 'status-dot--connected' : backendOnline === false ? 'status-dot--offline' : 'status-dot--checking'}`} />
          <span>
            {backendOnline === true
              ? `FastAPI Connected (${new URL(API_BASE_URL).port || '80'})`
              : backendOnline === false
                ? 'API Offline (Click to retry)'
                : 'Checking API...'}
            </span>
          </button>
      </div>
    </aside>
    <main className="main-content">
      {page === 'dashboard' && <Dashboard navigate={navigate} inventoryCount={inventory.length} backendOnline={backendOnline} onRetry={checkHealth} />}
      {page === 'checker' && <Checker
        algorithms={algorithmsList}
        selectedAlgorithm={selectedAlgorithm}
        setSelectedAlgorithm={setSelectedAlgorithm}
        useCase={useCase}
        setUseCase={setUseCase}
        assessment={assessment}
        isAssessing={isAssessing}
        assessError={assessError}
        assess={handleAssess}
      />}
      {page === 'inventory' && <Inventory
        inventory={inventory}
        isUploading={isUploading}
        uploadMessage={uploadMessage}
        onUpload={() => fileInput.current?.click()}
      />}
      {page === 'reports' && <Reports
        inventory={inventory}
        reportSummary={reportSummary}
        summaryLoading={summaryLoading}
        isDownloading={isDownloading}
        download={handleDownloadReport}
        navigate={navigate}
      />}
      {page === 'roadmap' && <Roadmap />}
      {page === 'about' && <About />}
    </main>
    <input ref={fileInput} className="visually-hidden" type="file" accept=".csv,text/csv" onChange={(event) => handleCsvUpload(event.target.files?.[0])} />
  </div>
}

function Dashboard({
  navigate,
  inventoryCount,
  backendOnline,
  onRetry,
}: {
  navigate: (page: Page) => void
  inventoryCount: number
  backendOnline: boolean | null
  onRetry: () => void
}) {
  return <>
    <section className="hero">
      <div className="hero-orbit hero-orbit-one" /><div className="hero-orbit hero-orbit-two" />
      <div className="hero-copy">
        <div className="eyebrow-line"><span className="eyebrow-icon"><Icon name="spark" size={14} /></span><Text as="span" className="eyebrow">QUANTUM READINESS STARTS HERE</Text></div>
        <Text as="h1" className="hero-title">Secure today.<br /><span>Prepare for quantum.</span></Text>
        <Text className="hero-description">Understand how quantum computing affects your cryptography and map a clear path toward post-quantum security with NIST standards.</Text>
        <div className="hero-actions">
          <Button onClick={() => navigate('checker')} icon="shield">Check an algorithm</Button>
          <Button onClick={() => navigate('roadmap')} variant="secondary">View migration roadmap <Icon name="arrow" /></Button>
        </div>
      </div>
      <div className="quantum-visual" aria-hidden="true">
        <div className="sphere sphere-outer"><div className="sphere sphere-inner"><Icon name="lock" size={30} /></div></div>
        <span className="particle p1" /><span className="particle p2" /><span className="particle p3" /><span className="particle p4" />
      </div>
    </section>

    {backendOnline === false && (
      <div className="feedback feedback--error" style={{ marginTop: '24px' }}>
        <Icon name="alert" />
        <Text>
          <strong>FastAPI Backend Offline:</strong> The backend at <code>{import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8003'}</code> is currently unreachable. Start it with <code>python -m uvicorn backend.app:app --reload</code>.{' '}
          <button onClick={onRetry} style={{ textDecoration: 'underline', background: 'transparent', border: 0, color: 'inherit', fontWeight: 700, cursor: 'pointer' }}>Retry connection</button>
        </Text>
      </div>
    )}

    <section className="section-block">
      <div className="section-heading">
        <div><Text as="span" className="eyebrow">YOUR QUANTUM-SAFE WORKSPACE</Text><Text as="h2">Start an assessment</Text></div>
        <Text>Practical tools for understanding and planning your cryptographic transition.</Text>
      </div>
      <div className="quick-grid">
        <QuickCard icon="shield" number="01" title="Security Checker" description="Assess an algorithm’s exposure to Shor’s and Grover’s attacks and identify NIST alternatives." accent="violet" onClick={() => navigate('checker')} cta="Assess an algorithm" />
        <QuickCard icon="database" number="02" title="Asset Inventory" description="Upload your cryptographic inventory CSV and evaluate asset-level quantum risk." accent="teal" onClick={() => navigate('inventory')} cta={inventoryCount ? `Review ${inventoryCount} assets` : 'Upload inventory'} />
        <QuickCard icon="chart" number="03" title="Assessment Reports" description="Summarize actual inventory findings and export an RFC-4180 CSV assessment." accent="lavender" onClick={() => navigate('reports')} cta="View reports" />
      </div>
    </section>

    <section className="roadmap-preview">
      <div className="roadmap-copy">
        <Text as="span" className="eyebrow">MIGRATION ROADMAP</Text>
        <Text as="h2">A measured path to<br />quantum readiness</Text>
        <Text>Migration is a journey, not a switch. Move from discovery to validated deployment with a structured, risk-informed plan.</Text>
        <Button variant="secondary" onClick={() => navigate('roadmap')}>Explore all six stages <Icon name="arrow" /></Button>
      </div>
      <Card className="roadmap-mini" glow="violet">
        {roadmapSteps.slice(0, 4).map(([title, description], index) => <div className="mini-step" key={title}>
          <div className="step-marker"><span>{String(index + 1).padStart(2, '0')}</span></div>
          <div><Text as="h3">{title}</Text><Text>{description}</Text></div>
        </div>)}
        <div className="mini-fade">+ 2 more validation stages</div>
      </Card>
    </section>
    <div className="disclaimer"><Icon name="info" /><Text><strong>Educational guidance only.</strong> QuantumSafe supports planning and awareness. It does not perform a formal security audit or automatically migrate production systems.</Text></div>
  </>
}

function QuickCard({ icon, number, title, description, accent, onClick, cta }: { icon: IconName; number: string; title: string; description: string; accent: string; onClick: () => void; cta: string }) {
  return <Card className={`quick-card quick-card--${accent}`}>
    <div className="quick-top"><span className="quick-icon"><Icon name={icon} size={22} /></span><span className="card-number">{number}</span></div>
    <Text as="h3">{title}</Text><Text>{description}</Text>
    <button className="text-link" onClick={onClick}>{cta}<Icon name="arrow" size={16} /></button>
  </Card>
}

function Checker({
  algorithms,
  selectedAlgorithm,
  setSelectedAlgorithm,
  useCase,
  setUseCase,
  assessment,
  isAssessing,
  assessError,
  assess,
}: {
  algorithms: Array<{ name: string; family: string; description: string; useCases: string[]; risk: Risk }>
  selectedAlgorithm: string
  setSelectedAlgorithm: (value: string) => void
  useCase: string
  setUseCase: (value: string) => void
  assessment: AssessResponse | null
  isAssessing: boolean
  assessError: string | null
  assess: () => void
}) {
  const current = algorithms.find((item) => item.name === selectedAlgorithm) || algorithms[0]

  return <>
    <PageHeader eyebrow="SECURITY CHECKER" title="Assess quantum exposure" description="Select a cryptographic algorithm and its use case to evaluate exposure with the FastAPI security rules engine." />
    <div className="checker-layout">
      <Card className="checker-form" glow="violet">
        <div className="card-heading-icon"><Icon name="shield" /></div>
        <Text as="h2">Algorithm assessment</Text>
        <Text className="muted">The use-case menu updates dynamically based on the selected algorithm.</Text>
        <SelectField label="Cryptographic algorithm" value={selectedAlgorithm} onChange={setSelectedAlgorithm} options={algorithms.map((item) => item.name)} hint={current?.description} disabled={isAssessing} />
        <SelectField label="Primary use case" value={useCase} onChange={setUseCase} options={current?.useCases || []} disabled={isAssessing} />
        <Button onClick={assess} icon="spark" loading={isAssessing}>
          {isAssessing ? 'Evaluating security rules...' : 'Assess security'}
        </Button>
      </Card>
      <div className="algorithm-browser">
        <Text as="span" className="eyebrow">SUPPORTED ALGORITHMS</Text>
        <div className="algorithm-grid">
          {algorithms.map((item) => <button key={item.name} className={`algorithm-tile ${item.name === selectedAlgorithm ? 'algorithm-tile--active' : ''}`} onClick={() => setSelectedAlgorithm(item.name)}>
            <span><strong>{item.name}</strong><small>{item.family}</small></span><RiskPill risk={item.risk} />
          </button>)}
        </div>
      </div>
    </div>

    {assessError && (
      <div className="feedback feedback--error" style={{ marginTop: '24px' }}>
        <Icon name="alert" />
        <Text><strong>Assessment Failed:</strong> {assessError}</Text>
      </div>
    )}

    {assessment && <AssessmentResult result={assessment} />}
    {!assessment && !assessError && <Card className="info-strip"><Icon name="info" /><Text><strong>Why use case matters:</strong> The right post-quantum replacement depends on whether an algorithm is used for bulk encryption, key establishment, or digital signatures.</Text></Card>}
  </>
}

function AssessmentResult({ result }: { result: AssessResponse }) {
  const riskClass = result.risk_level.toLowerCase().replace(/ /g, '-')
  const riskLabel = result.risk_level === 'High risk' ? 'HIGH' : result.risk_level === 'Quantum-safe' ? 'SAFE' : result.risk_level === 'Invalid use case' ? 'INVALID' : 'LOWER'

  return <section className="result-section">
    <div className="section-heading">
      <div>
        <Text as="span" className="eyebrow">BACKEND ASSESSMENT RESULT</Text>
        <Text as="h2">{result.algorithm} · {result.use_case}</Text>
      </div>
      <RiskPill risk={result.risk_level} />
    </div>
    <div className="result-grid">
      <Card className={`risk-visual risk-visual--${riskClass}`}>
        <div className="risk-ring">
          <div>
            <span>RISK</span>
            <strong>{riskLabel}</strong>
          </div>
        </div>
        <Text>
          {result.risk_level === 'High risk'
            ? 'Migration planning recommended'
            : result.risk_level === 'Quantum-safe'
            ? 'Designed for post-quantum use'
            : result.risk_level === 'Invalid use case'
            ? 'Cryptographic role mismatch'
            : 'Review key strength & lifetime'}
        </Text>
        <span className="score-badge">
          Prioritization Score: {result.prioritization_score}/100
        </span>
      </Card>
      <Card className="result-details">
        <ResultDetail icon="alert" title="Risk explanation" text={result.reason} />
        <ResultDetail icon="spark" title="Quantum attack profile" text={result.quantum_threat} />
        <ResultDetail icon="shield" title="Recommended approach" text={result.recommendation} highlight />
        <ResultDetail icon="book" title="NIST Reference standard" text={result.reference_citation || (result.references[0] ? `${result.references[0].standard_id} · ${result.references[0].title}` : 'NIST PQC Standards')} />
        {result.caveats && <div className="result-detail-caveat"><Text>{result.caveats}</Text></div>}
      </Card>
    </div>
  </section>
}

function ResultDetail({ icon, title, text, highlight }: { icon: IconName; title: string; text: string; highlight?: boolean }) {
  return <div className={`result-detail ${highlight ? 'result-detail--highlight' : ''}`}><span className="detail-icon"><Icon name={icon} /></span><div><Text as="h3">{title}</Text><Text>{text}</Text></div></div>
}

function Inventory({
  inventory,
  isUploading,
  uploadMessage,
  onUpload,
}: {
  inventory: InventoryRow[]
  isUploading: boolean
  uploadMessage: { type: 'success' | 'error'; text: string } | null
  onUpload: () => void
}) {
  return <>
    <PageHeader
      eyebrow="ASSET INVENTORY"
      title="Map your cryptographic footprint"
      description="Upload a CSV inventory to validate and assess each asset with the FastAPI security rules engine."
      action={<Button onClick={onUpload} icon="upload" loading={isUploading}>{isUploading ? 'Assessing...' : 'Upload CSV'}</Button>}
    />
    <Card className="upload-zone">
      <div className="upload-icon"><Icon name={isUploading ? 'spinner' : 'upload'} size={28} /></div>
      <Text as="h2">{isUploading ? 'Assessing cryptographic assets...' : 'Drop in your cryptographic inventory'}</Text>
      <Text>{isUploading ? 'FastAPI is validating columns and running security rules against NIST PQC standards.' : 'Choose a comma-separated file to evaluate your organization’s quantum risk.'}</Text>
      <Button variant="secondary" onClick={onUpload} icon="file" disabled={isUploading}>
        {isUploading ? 'Evaluating...' : 'Choose CSV file'}
      </Button>
      <div className="format-box">
        <span>REQUIRED FORMAT</span>
        <code>asset_name, algorithm, use_case</code>
        <small>Optional fields: environment, owner, criticality, key_size</small>
      </div>
    </Card>
    {uploadMessage && <div className={`feedback feedback--${uploadMessage.type}`}><Icon name={uploadMessage.type === 'success' ? 'check' : 'alert'} /><Text>{uploadMessage.text}</Text></div>}
    <section className="table-section">
      <div className="section-heading">
        <div><Text as="span" className="eyebrow">ASSESSMENT TABLE</Text><Text as="h2">Inventory findings</Text></div>
        <span className="count-label">{inventory.length} {inventory.length === 1 ? 'asset' : 'assets'}</span>
      </div>
      <Card className="table-card">
        {inventory.length ? <div className="table-scroll"><table>
          <thead><tr><th>Asset name</th><th>Algorithm</th><th>Use case</th><th>Risk level</th><th>Recommended alternative</th></tr></thead>
          <tbody>{inventory.map((row, index) => <tr key={`${row.asset || row.asset_name}-${index}`}>
            <td><span className="asset-cell"><Icon name="file" />{row.asset || row.asset_name}</span></td>
            <td><strong>{row.algorithm}</strong></td>
            <td>{row.useCase || row.use_case}</td>
            <td><RiskPill risk={row.risk || row.risk_level} /></td>
            <td>{row.alternative || row.recommendation}</td>
          </tr>)}</tbody>
        </table></div> : <EmptyState icon="database" title="No inventory uploaded yet" description="Upload a correctly formatted CSV to generate asset-level findings with the backend rules engine. Results will appear in this table." action={<Button onClick={onUpload} variant="secondary">Upload your first inventory</Button>} />}
      </Card>
    </section>
  </>
}

function Reports({
  inventory,
  reportSummary,
  summaryLoading,
  isDownloading,
  download,
  navigate,
}: {
  inventory: InventoryRow[]
  reportSummary: ReportSummary | null
  summaryLoading: boolean
  isDownloading: boolean
  download: () => void
  navigate: (page: Page) => void
}) {
  // Compute counts from backend summary if available, else derive from inventory rows
  const counts = useMemo(() => {
    if (reportSummary && reportSummary.risk_distribution) {
      return {
        high: reportSummary.risk_distribution['High risk'] || 0,
        lower: reportSummary.risk_distribution['Lower quantum risk'] || 0,
        safe: reportSummary.risk_distribution['Quantum-safe'] || 0,
      }
    }
    return {
      high: inventory.filter((row) => (row.risk || row.risk_level) === 'High risk').length,
      lower: inventory.filter((row) => (row.risk || row.risk_level) === 'Lower quantum risk').length,
      safe: inventory.filter((row) => (row.risk || row.risk_level) === 'Quantum-safe').length,
    }
  }, [reportSummary, inventory])

  const guidanceList = reportSummary?.migration_guidance || [
    counts.high ? `Prioritize the ${counts.high} high-risk asset(s) using RSA or elliptic-curve cryptography.` : 'Continue monitoring for public-key algorithms that require migration.',
    'Confirm each asset’s data lifetime, business criticality, and external dependencies.',
    'Test standardized alternatives (NIST FIPS 203/204/205) in a controlled environment before planning deployment.',
  ]

  return <>
    <PageHeader
      eyebrow="REPORTS"
      title="Turn findings into action"
      description="Summaries and recommendations are generated dynamically by FastAPI from your uploaded cryptographic inventory."
      action={<Button icon="download" onClick={download} disabled={!inventory.length} loading={isDownloading}>{isDownloading ? 'Generating...' : 'Download CSV report'}</Button>}
    />
    {!inventory.length ? <Card className="reports-empty"><EmptyState icon="chart" title="Your report is waiting for data" description="Upload a cryptographic inventory first. QuantumSafe will calculate the risk distribution from those actual assets—never from placeholder metrics." action={<Button onClick={() => navigate('inventory')} icon="upload">Upload inventory</Button>} /></Card> : <>
      <div className="summary-grid">
        <SummaryCard label="Assets assessed" value={inventory.length} icon="database" />
        <SummaryCard label="High-risk assets" value={counts.high} icon="alert" tone="danger" />
        <SummaryCard label="Lower quantum risk" value={counts.lower} icon="lock" tone="warning" />
        <SummaryCard label="Quantum-safe assets" value={counts.safe} icon="shield" tone="safe" />
      </div>
      <div className="report-grid">
        <Card className="distribution-card">
          <Text as="span" className="eyebrow">ACTUAL INVENTORY</Text><Text as="h2">Risk distribution</Text>
          {summaryLoading ? <div style={{ padding: '20px 0', color: 'var(--muted)' }}><Icon name="spinner" /> Calculating backend metrics...</div> : (
            <div className="distribution">
              {[['High risk', counts.high, 'high'], ['Lower quantum risk', counts.lower, 'lower'], ['Quantum-safe', counts.safe, 'safe']].map(([label, count, tone]) => {
                const percentage = inventory.length ? (Number(count) / inventory.length) * 100 : 0
                return <div className="distribution-row" key={label}>
                  <div><span>{label}</span><strong>{count} ({Math.round(percentage)}%)</strong></div>
                  <div className="bar"><span className={`bar-${tone}`} style={{ width: `${percentage}%` }} /></div>
                </div>
              })}
            </div>
          )}
        </Card>
        <Card className="recommendations">
          <Text as="span" className="eyebrow">RECOMMENDED NEXT STEPS</Text><Text as="h2">Migration guidance</Text>
          {guidanceList.map((guidanceText, idx) => (
            <Recommendation key={idx} number={String(idx + 1).padStart(2, '0')} text={guidanceText} />
          ))}
          <Button variant="secondary" onClick={() => navigate('roadmap')}>Open migration roadmap <Icon name="arrow" /></Button>
        </Card>
      </div>
      <div className="feedback feedback--success">
        <Icon name="check" />
        <Text>Report ready. The downloadable CSV contains {inventory.length} assessed {inventory.length === 1 ? 'asset' : 'assets'} and their recommended alternatives.</Text>
      </div>
    </>}
  </>
}

function SummaryCard({ label, value, icon, tone = 'default' }: { label: string; value: number; icon: IconName; tone?: string }) {
  return <Card className={`summary-card summary-card--${tone}`}><span className="summary-icon"><Icon name={icon} /></span><div><strong>{value}</strong><span>{label}</span></div></Card>
}

function Recommendation({ number, text }: { number: string; text: string }) {
  return <div className="recommendation"><span>{number}</span><Text>{text}</Text></div>
}

function Roadmap() {
  return <>
    <PageHeader eyebrow="QUANTUM MIGRATION ROADMAP" title="Build a defensible transition plan" description="Six practical stages for moving from cryptographic discovery to a validated quantum-safe deployment." />
    <div className="roadmap-hero">
      <Card className="roadmap-callout" glow="teal"><Icon name="route" size={28} /><div><Text as="h2">Migration is a managed program</Text><Text>QuantumSafe helps you understand and plan the work. It does not automatically replace algorithms or deploy changes to your systems.</Text></div></Card>
    </div>
    <div className="roadmap-full">
      {roadmapSteps.map(([title, description], index) => <div className="roadmap-stage" key={title}>
        <div className="stage-track"><span>{String(index + 1).padStart(2, '0')}</span>{index < roadmapSteps.length - 1 && <i />}</div>
        <Card className="stage-card">
          <div className="stage-meta"><span>STAGE {index + 1}</span><Icon name={index < 3 ? 'database' : index < 5 ? 'spark' : 'check'} /></div>
          <Text as="h2">{title}</Text><Text>{description}</Text>
          <div className="stage-note">{index === 0 ? 'Outcome: complete inventory' : index === 1 ? 'Outcome: exposure map' : index === 2 ? 'Outcome: prioritized backlog' : index === 3 ? 'Outcome: target architecture' : index === 4 ? 'Outcome: tested implementation' : 'Outcome: validated rollout'}</div>
        </Card>
      </div>)}
    </div>
  </>
}

function About() {
  return <>
    <PageHeader eyebrow="ABOUT QUANTUMSAFE" title="Clear guidance for a changing security landscape" description="An educational workspace for understanding post-quantum cryptography and preparing responsible migration plans." />
    <div className="about-grid">
      <Card className="about-primary" glow="violet"><div className="large-brand-mark"><Logo /></div><Text as="h2">Why quantum readiness matters</Text><Text>Cryptographically relevant quantum computers could undermine widely deployed public-key systems. Organizations can begin preparing now by discovering where cryptography is used, understanding risk, and testing standardized alternatives.</Text><Text>QuantumSafe translates that complex topic into practical, use-case-specific guidance without overstating certainty or automating sensitive system changes.</Text></Card>
      <div className="about-stack">
        <Card><span className="about-icon"><Icon name="book" /></span><Text as="h3">Standards-informed</Text><Text>Algorithm guidance references finalized NIST post-quantum cryptography standards (FIPS 203, 204, 205) and transition resources.</Text></Card>
        <Card><span className="about-icon"><Icon name="shield" /></span><Text as="h3">Risk-aware</Text><Text>Symmetric, public-key, and post-quantum algorithms are assessed according to their distinct security profiles.</Text></Card>
        <Card><span className="about-icon"><Icon name="info" /></span><Text as="h3">Educational by design</Text><Text>Results support awareness and planning, not formal compliance, certification, or professional security assurance.</Text></Card>
      </div>
    </div>
  </>
}

function EmptyState({ icon, title, description, action }: { icon: IconName; title: string; description: string; action: ReactNode }) {
  return <div className="empty-state"><span><Icon name={icon} size={28} /></span><Text as="h2">{title}</Text><Text>{description}</Text>{action}</div>
}

export default App
