import { useEffect, useMemo, useState } from 'react'
import {
  Activity, ArrowUpRight, BadgeCheck, BookOpen, Check, ChevronRight, CircleHelp,
  Copy, ExternalLink, FileSearch, Github, Globe2, LockKeyhole, Radar, ScanSearch,
  Shield, ShieldAlert, ShieldCheck, Terminal, Zap, RefreshCw, Search, Clock3,
  AlertTriangle
} from 'lucide-react'

type Tab = 'radar' | 'scanner' | 'report'
type Finding = { name: string; status: 'Present' | 'Not detected' | 'Review'; detail: string; severity: 'good' | 'warn' | 'info' }

type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
type ThreatReference = { url: string; source?: string; tags?: string[] }
type AffectedProduct = { vendor?: string; product?: string; versions?: { version?: string; versionType?: string; status?: string; lessThan?: string; lessThanOrEqual?: string; changes?: { at?: string; status?: string }[] }[] }
type ThreatItem = {
  id: string
  description: string
  published: string
  modified: string
  severity: ThreatSeverity
  score: number | null
  sourceUrl: string
  weaknesses: string[]
  references: ThreatReference[]
  affectedProducts: AffectedProduct[]
}
type NvdCve = {
  id?: string
  descriptions?: Array<{ lang: string; value: string }>
  published?: string
  lastModified?: string
  metrics?: Record<string, Array<{
    cvssData?: {
      baseScore?: number
      baseSeverity?: string
      vectorString?: string
    }
  }>>
  weaknesses?: Array<{
    description?: Array<{ lang: string; value: string }>
  }>
  references?: ThreatReference[]
  configurations?: Array<{
    nodes?: Array<{
      cpeMatch?: Array<{
        vulnerable?: boolean
        criteria?: string
        versionStartIncluding?: string
        versionStartExcluding?: string
        versionEndIncluding?: string
        versionEndExcluding?: string
      }>
      children?: unknown[]
    }>
  }>
}

function getCveSeverity(cve: NvdCve): { severity: ThreatSeverity; score: number | null } {
  const metrics = cve.metrics || {}
  const candidates = [metrics.cvssMetricV40, metrics.cvssMetricV31, metrics.cvssMetricV30, metrics.cvssMetricV2]
  for (const group of candidates) {
    const metric = group?.[0]
    if (!metric?.cvssData) continue
    const score = typeof metric.cvssData.baseScore === 'number' ? metric.cvssData.baseScore : null
    const raw = (metric.cvssData.baseSeverity || '').toUpperCase()
    const severity: ThreatSeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(raw)
      ? raw as ThreatSeverity
      : score === null ? 'UNKNOWN' : score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score > 0 ? 'LOW' : 'UNKNOWN'
    return { severity, score }
  }
  return { severity: 'UNKNOWN', score: null }
}

function mapNvdItem(item: NvdCve): ThreatItem {
  const cve = item
  const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No English summary was supplied by NVD.'
  const { severity, score } = getCveSeverity(cve)
  return {
    id: cve.id || 'Unknown CVE',
    description,
    published: cve.published || '',
    modified: cve.lastModified || '',
    severity,
    score,
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id || '')}`,
    weaknesses: (cve.weaknesses || []).flatMap(group => (group.description || []).filter(d => d.lang === 'en').map(d => d.value)).filter((value, index, all) => all.indexOf(value) === index),
    references: cve.references || [],
    affectedProducts: (cve.configurations || []).flatMap(configuration => (configuration.nodes || []).flatMap(node => (node.cpeMatch || []).filter(match => match.vulnerable).map(match => {
      const parts = (match.criteria || '').split(':')
      const versionRange = [match.versionStartIncluding ? `>= ${match.versionStartIncluding}` : '', match.versionStartExcluding ? `> ${match.versionStartExcluding}` : '', match.versionEndIncluding ? `<= ${match.versionEndIncluding}` : '', match.versionEndExcluding ? `< ${match.versionEndExcluding}` : ''].filter(Boolean).join(' · ')
      return { vendor: parts[3] || 'Unknown vendor', product: parts[4] || 'Unknown product', versions: [{ version: parts[5] && parts[5] !== '*' ? parts[5] : '', status: 'vulnerable', ...(versionRange ? { lessThan: versionRange } : {}) }] }
    }))).filter((product, index, all) => all.findIndex(other => other.vendor === product.vendor && other.product === product.product && JSON.stringify(other.versions) === JSON.stringify(product.versions)) === index),
  }
}

const SOURCES = [
  { name: 'PHP Security Advisories', kind: 'Primary source', detail: 'Official PHP security announcements and release information.', url: 'https://www.php.net/releases/', icon: ShieldCheck },
  { name: 'WATCHPHP CVE Intelligence', kind: 'CVE source', detail: 'Explore published CVE records surfaced by WATCHPHP; verify details with the official record.', url: 'https://nvd.nist.gov/vuln/search/results?query=PHP&search_type=all', icon: Radar },
  { name: 'CVE Program', kind: 'Identifiers & records', detail: 'Look up a CVE identifier and its published record.', url: 'https://www.cve.org/', icon: BookOpen },
  { name: 'OSV Database', kind: 'Open source advisories', detail: 'Search package-level vulnerability data and affected versions.', url: 'https://osv.dev/list?q=PHP', icon: Activity },
]

const HEADER_RULES = [
  { key: 'strict-transport-security', label: 'Strict-Transport-Security', description: 'Helps browsers enforce HTTPS after a secure visit.', severity: 'warn' as const },
  { key: 'content-security-policy', label: 'Content-Security-Policy', description: 'Can reduce the impact of some script injection attacks.', severity: 'warn' as const },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', description: 'Use nosniff to reduce MIME type sniffing risks.', severity: 'warn' as const },
  { key: 'referrer-policy', label: 'Referrer-Policy', description: 'Controls how much referrer information browsers send.', severity: 'info' as const },
  { key: 'permissions-policy', label: 'Permissions-Policy', description: 'Restricts access to selected browser features.', severity: 'info' as const },
  { key: 'x-frame-options', label: 'X-Frame-Options', description: 'Legacy framing control; CSP frame-ancestors is more flexible.', severity: 'info' as const },
]

function analyzeHeaders(raw: string): Finding[] {
  const normalized = raw.toLowerCase()
  return HEADER_RULES.map(rule => {
    const found = normalized.split(/\r?\n/).some(line => line.startsWith(rule.key + ':'))
    const valueLine = normalized.split(/\r?\n/).find(line => line.startsWith(rule.key + ':')) || ''
    const configured = found && valueLine.split(':').slice(1).join(':').trim().length > 0
    return {
      name: rule.label,
      status: configured ? 'Present' : 'Not detected',
      detail: configured ? `Header found in the supplied text. Review its value and application context.` : rule.description,
      severity: configured ? 'good' : rule.severity
    }
  })
}


type OsvVulnerability = {
  id: string
  summary?: string
  details?: string
  published?: string
  modified?: string
  aliases?: string[]
  references?: { type?: string; url: string }[]
  severity?: { type?: string; score?: string }[]
  affected?: { package?: { ecosystem?: string; name?: string }; ranges?: { type?: string; events?: { introduced?: string; fixed?: string; last_affected?: string }[] }[] }[]
}
type OsvQueryResult = { vulns?: OsvVulnerability[] }

function osvSeverity(item: OsvVulnerability): ThreatSeverity {
  const vector = item.severity?.find(entry => entry.type?.toUpperCase().includes('CVSS'))?.score || ''
  const match = vector.match(/(?:^|\\/)(\\d+(?:\\.\\d+)?)$/)
  const score = match ? Number(match[1]) : NaN
  if (!Number.isFinite(score)) return 'UNKNOWN'
  return score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : score > 0 ? 'LOW' : 'UNKNOWN'
}

const DEFAULT_OSV_PACKAGES = [
  'laravel/framework', 'symfony/symfony', 'guzzlehttp/guzzle', 'phpunit/phpunit',
  'twig/twig', 'monolog/monolog', 'doctrine/orm', 'drupal/core'
]

function App() {
  const [tab, setTab] = useState<Tab>('radar')
  const [headers, setHeaders] = useState('')
  const [targetLabel, setTargetLabel] = useState('')
  const [ran, setRan] = useState(false)
  const [copied, setCopied] = useState(false)
  const [threats, setThreats] = useState<ThreatItem[]>([])
  const [feedState, setFeedState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [feedError, setFeedError] = useState('')
  const [lastUpdated, setLastUpdated] = useState('')
  const [threatSearch, setThreatSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [dateFilter, setDateFilter] = useState('119')
  const [productFilter, setProductFilter] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [selectedThreat, setSelectedThreat] = useState<ThreatItem | null>(null)
  const [osvPackage, setOsvPackage] = useState('')
  const [osvItems, setOsvItems] = useState<OsvVulnerability[]>([])
  const [osvState, setOsvState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [osvError, setOsvError] = useState('')
  const [osvUpdated, setOsvUpdated] = useState('')
  const [osvRefreshing, setOsvRefreshing] = useState(false)
  const [osvQueryLabel, setOsvQueryLabel] = useState('Popular Packagist packages')

  async function loadOsvFeed(packageName?: string) {
    setOsvRefreshing(true)
    setOsvState(osvItems.length ? 'ready' : 'loading')
    setOsvError('')
    const packages = (packageName?.trim() ? [packageName.trim()] : DEFAULT_OSV_PACKAGES)
      .filter((name, index, all) => all.indexOf(name) === index)
    setOsvQueryLabel(packageName?.trim() || 'Popular Packagist packages')
    try {
      const response = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          queries: packages.map(name => ({ package: { ecosystem: 'Packagist', name } }))
        })
      })
      if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}.`)
      const payload = await response.json() as { results?: OsvQueryResult[] }
      const items = (payload.results || []).flatMap(result => result.vulns || [])
        .filter((item, index, all) => Boolean(item.id) && all.findIndex(other => other.id === item.id) === index)
        .sort((a, b) => Date.parse(b.published || b.modified || '') - Date.parse(a.published || a.modified || ''))
      setOsvItems(items)
      setOsvState('ready')
      setOsvUpdated(new Date().toISOString())
      if (!items.length) setOsvError(`No advisories returned for ${packageName?.trim() || 'the selected package set'}. Try a specific Composer package name.`)
    } catch (error) {
      setOsvState('error')
      setOsvError(error instanceof Error ? error.message : 'Could not load OSV data. Check your connection and try again.')
    } finally {
      setOsvRefreshing(false)
    }
  }

  async function loadThreatFeed(manual = false) {
    if (manual) setRefreshing(true)
    setFeedState(current => threats.length ? current : 'loading')
    setFeedError('')
    try {
      const end = new Date()
      const start = new Date(end.getTime() - Number(dateFilter) * 24 * 60 * 60 * 1000)
      const iso = (date: Date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z')
      const params = new URLSearchParams({
        keywordSearch: 'PHP',
        resultsPerPage: '40',
        pubStartDate: iso(start),
        pubEndDate: iso(end),
      })
      const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0/?${params.toString()}`, {
        headers: { Accept: 'application/json' },
      })
      if (!response.ok) {
        const detail = (await response.text()).slice(0, 180).replace(/\s+/g, ' ')
        throw new Error(response.status === 429 ? 'NVD rate limit reached. Wait a little before refreshing.' : `NVD returned HTTP ${response.status}${detail ? `: ${detail}` : '.'}`)
      }
      const payload = await response.json() as { vulnerabilities?: { cve?: NvdCve }[] }
      const items = (payload.vulnerabilities || []).map(row => mapNvdItem(row.cve || {})).filter(item => item.id !== 'Unknown CVE')
      items.sort((a, b) => Date.parse(b.published) - Date.parse(a.published))
      setThreats(items)
      setFeedState('ready')
      setLastUpdated(new Date().toISOString())
      if (!items.length) setFeedError('NVD returned no matching PHP keyword records in this 119-day window.')
    } catch (error) {
      setFeedState('error')
      setFeedError(error instanceof Error ? error.message : 'Could not load NVD data. Check the connection and try again.')
    } finally {
      setRefreshing(false)
    }
  }

  useEffect(() => {
    void loadThreatFeed()
    // Fetch once on initial load; manual refresh is available in the Threat Radar.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dateFilter])

  useEffect(() => {
    void loadOsvFeed()
    // Load published OSV advisories for a small set of common Packagist packages.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const filteredThreats = useMemo(() => threats.filter(item => {
    const productText = item.affectedProducts.map(product => `${product.vendor} ${product.product}`).join(' ')
    const matchesSearch = `${item.id} ${item.description} ${productText}`.toLowerCase().includes(threatSearch.toLowerCase())
    const matchesProduct = !productFilter || productText.toLowerCase().includes(productFilter.toLowerCase())
    return matchesSearch && matchesProduct && (severityFilter === 'ALL' || item.severity === severityFilter)
  }), [threats, threatSearch, severityFilter, productFilter])
  const severityCounts = useMemo(() => (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as ThreatSeverity[]).map(severity => ({
    severity,
    count: threats.filter(item => item.severity === severity).length,
  })), [threats])
  const highestCount = Math.max(1, ...severityCounts.map(item => item.count))

  const findings = useMemo(() => analyzeHeaders(headers), [headers])
  const present = findings.filter(f => f.status === 'Present').length
  const score = Math.round((present / findings.length) * 100)
  const reportText = useMemo(() => {
    const label = targetLabel.trim() || 'Unlabelled assessment'
    return [
      'PHP WATCH — HEADER REVIEW',
      `Target label: ${label}`,
      `Headers detected: ${present}/${findings.length}`,
      `Coverage indicator: ${score}%`,
      '',
      ...findings.map(f => `${f.status === 'Present' ? '[FOUND]' : '[REVIEW]'} ${f.name} — ${f.detail}`),
      '',
      'Limitations: This is a lightweight header-presence review of user-supplied text, not a full security audit. Missing headers are not proof of a vulnerability.',
      'Generated locally by PHP WATCH.'
    ].join('\n')
  }, [targetLabel, present, findings, score])

  async function copyReport() {
    try {
      await navigator.clipboard.writeText(reportText)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setTab('report')
    }
  }

  function runScan() {
    setRan(true)
    setTab('scanner')
  }

  const tabs = [
    { id: 'radar' as const, label: 'Threat Radar', icon: Radar },
    { id: 'scanner' as const, label: 'Safe Scanner', icon: ScanSearch },
    { id: 'report' as const, label: 'Shareable Report', icon: FileSearch },
  ]

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={() => setTab('radar')} aria-label="PHP WATCH home">
        <span className="brand-mark"><Terminal size={21}/></span>
        <span><strong>PHP<span className="green">WATCH</span></strong><small>SECURITY INTELLIGENCE</small></span>
      </a>
      <div className="side-label">WORKSPACE</div>
      <nav className="side-nav">
        {tabs.map(item => <button key={item.id} className={`nav-item ${tab === item.id ? 'active' : ''}`} onClick={() => setTab(item.id)}>
          <item.icon size={17}/><span>{item.label}</span>{tab === item.id && <ChevronRight size={15} className="nav-arrow"/>}
        </button>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="system-card"><span className="live-dot"/><div><strong>Local analysis</strong><small>No target requests sent</small></div></div>
        <a className="github-link" href="https://github.com/imaaiagent/PHPWATCH" target="_blank" rel="noopener noreferrer"><Github size={16}/> View on GitHub <ArrowUpRight size={14}/></a>
        <div className="side-foot">COMMUNITY PROJECT <span>•</span> MVP 0.1.0</div>
      </div>
    </aside>

    <main className="main">
      <header className="topbar">
        <div className="breadcrumb"><span>Workspace</span><ChevronRight size={13}/><strong>{tabs.find(t => t.id === tab)?.label}</strong></div>
        <div className="top-status"><span className="live-dot"/> <span>Systems nominal</span><span className="status-divider"/> <span className="mono">v0.1.0</span></div>
      </header>

      <div className="content">
        <section className="hero">
          <div className="hero-copy">
            <div className="eyebrow"><span className="eyebrow-line"/> OPEN SECURITY TOOLKIT <span className="eyebrow-line"/></div>
            <h1>See the signal.<br/><span>Secure the stack.</span></h1>
            <p>Practical PHP security intelligence for developers. Grounded in primary sources, built for clarity.</p>
            <div className="hero-actions">
              <button className="btn-primary" onClick={() => setTab('scanner')}><ScanSearch size={16}/> Run header review <ChevronRight size={15}/></button>
              <a className="btn-quiet" href="https://www.php.net/releases/" target="_blank" rel="noreferrer">Official PHP source <ExternalLink size={14}/></a>
            </div>
          </div>
          <div className="hero-graphic" aria-hidden="true">
            <div className="radar-ring ring-one"/><div className="radar-ring ring-two"/><div className="radar-ring ring-three"/>
            <div className="radar-cross horizontal"/><div className="radar-cross vertical"/>
            <div className="radar-sweep"/><span className="radar-point point-a"/><span className="radar-point point-b"/><span className="radar-point point-c"/>
            <div className="radar-center"><Shield size={27}/></div><span className="graphic-label label-a">SIGNAL / 01</span><span className="graphic-label label-b">MONITORING</span>
          </div>
        </section>

        <section className="metrics-grid">
          <Metric icon={<Globe2 size={17}/>} label="Primary sources" value="04" note="Official & recognized databases"/>
          <Metric icon={<ShieldCheck size={17}/>} label="Remote probing" value="OFF" note="No targets contacted"/>
          <Metric icon={<LockKeyhole size={17}/>} label="Data storage" value="NONE" note="Analysis stays in browser"/>
          <Metric icon={<Zap size={17}/>} label="Report engine" value={ran ? `${present}/6` : 'READY'} note={ran ? 'Header presence reviewed' : 'Awaiting supplied headers'}/>
        </section>

        <div className="section-heading">
          <div><div className="eyebrow left"><span className="eyebrow-line"/> INTELLIGENCE CONSOLE</div><h2>{tab === 'radar' ? 'Threat Radar' : tab === 'scanner' ? 'Safe Scanner' : 'Shareable Report'}</h2></div>
          <span className="pill"><span className="live-dot"/> MVP / ACTIVE</span>
        </div>

        {tab === 'radar' && <>
          <section className="panel live-feed-panel">
            <div className="panel-header live-feed-header"><div><div className="eyebrow left"><span className="live-dot"/> WATCHPHP / LIVE CVE DATA</div><h3>PHP vulnerability signal</h3><p>Published CVE records matching “PHP” in the selected time window, aggregated from published CVE records via the NVD API.</p></div><button className="btn-secondary refresh-btn" onClick={() => void loadThreatFeed(true)} disabled={refreshing}><RefreshCw size={15} className={refreshing ? 'spin' : ''}/>{refreshing ? 'Refreshing' : 'Refresh feed'}</button></div>
            <div className="feed-meta"><span className={`feed-status ${feedState}`}><span className="live-dot"/>{feedState === 'loading' ? 'Connecting to WATCHPHP feed' : feedState === 'error' ? 'Feed unavailable' : 'WATCHPHP feed connected'}</span><span><Clock3 size={13}/>{lastUpdated ? `Updated ${new Date(lastUpdated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Waiting for first sync'}</span><span>Upstream: NVD CVE API 2.0</span></div>
            {feedError && <div className={`feed-message ${feedState === 'error' ? 'error' : ''}`}><AlertTriangle size={15}/><span>{feedError} {feedState === 'error' && 'The rest of PHP WATCH remains available; the feed is not simulated.'}</span></div>}
            <section className="intel-overview">
              <div className="intel-overview-head"><div><span className="cve-section-label">THREAT INTELLIGENCE</span><h3>Vulnerability overview</h3><p>Derived from the CVE records currently loaded by WATCHPHP.</p></div><label className="date-filter">Window <select value={dateFilter} onChange={event => setDateFilter(event.target.value)}><option value="30">30 days</option><option value="60">60 days</option><option value="119">119 days</option></select></label></div>
              <div className="intel-stats"><div><span>Records loaded</span><strong>{threats.length}</strong></div><div><span>Critical + High</span><strong>{threats.filter(item => item.severity === 'CRITICAL' || item.severity === 'HIGH').length}</strong></div><div><span>With product data</span><strong>{threats.filter(item => item.affectedProducts.length > 0).length}</strong></div><div><span>Published this month</span><strong>{threats.filter(item => item.published && new Date(item.published) >= new Date(new Date().getFullYear(), new Date().getMonth(), 1)).length}</strong></div></div>
              <div className="trend-bars"><div className="trend-title">Severity distribution <span>Current result set</span></div>{severityCounts.map(item => <div className="trend-row" key={item.severity}><span>{item.severity}</span><div className="trend-track"><i className={`trend-${item.severity.toLowerCase()}`} style={{width:`${threats.length ? item.count / Math.max(1, threats.length) * 100 : 0}%`}}/></div><b>{item.count}</b></div>)}</div>
            </section>
            <div className="severity-overview">{severityCounts.map(item => <button key={item.severity} className={`severity-card severity-${item.severity.toLowerCase()} ${severityFilter === item.severity ? 'selected' : ''}`} onClick={() => setSeverityFilter(severityFilter === item.severity ? 'ALL' : item.severity)}><span>{item.severity}</span><strong>{feedState === 'loading' && !threats.length ? '—' : item.count}</strong><div className="severity-track"><i style={{ width: `${(item.count / highestCount) * 100}%` }}/></div></button>)}</div>
            <div className="feed-tools"><label className="feed-search"><Search size={15}/><input value={threatSearch} onChange={e => setThreatSearch(e.target.value)} placeholder="Search CVE IDs or descriptions"/></label><label className="severity-select"><span>Product</span><input className="product-filter-input" value={productFilter} onChange={e => setProductFilter(e.target.value)} placeholder="Vendor / product"/></label><label className="severity-select"><span>Severity</span><select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}><option value="ALL">All levels</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option><option value="UNKNOWN">Unscored</option></select></label></div>
            {feedState === 'loading' && !threats.length ? <div className="feed-empty"><RefreshCw size={18} className="spin"/><strong>Loading published records</strong><p>Fetching recent CVE entries for WATCHPHP. First load may take a moment.</p></div> : filteredThreats.length ? <div className="threat-list">{filteredThreats.map(item => <article className="threat-item" key={item.id}><div className="threat-severity-mark"/><div className="threat-main"><div className="threat-item-top"><button className="cve-title-button" onClick={() => setSelectedThreat(item)}>{item.id} <ChevronRight size={13}/></button><span className={`severity-pill ${item.severity.toLowerCase()}`}>{item.severity}{item.score !== null ? ` · ${item.score.toFixed(1)}` : ''}</span></div><p>{item.description}</p><div className="threat-foot"><span>Published {item.published ? new Date(item.published).toLocaleDateString() : 'date unavailable'}</span><span>Modified {item.modified ? new Date(item.modified).toLocaleDateString() : '—'}</span><button className="threat-detail-link" onClick={() => setSelectedThreat(item)}>View details <ChevronRight size={12}/></button></div></div></article>)}</div> : <div className="feed-empty"><Search size={18}/><strong>No matching records</strong><p>Try another search or severity filter.</p></div>}
            <div className="panel-note"><CircleHelp size={15}/><span>Live means WATCHPHP fetches published CVE records when this page loads or when refreshed; this is not a real-time attack monitor. “PHP” is a keyword search and may include records mentioning PHP outside the PHP runtime itself. Verify affected products and versions in the original CVE record.</span></div>
            <section className="osv-live-panel">
              <div className="osv-live-header">
                <div><div className="eyebrow left"><span className="live-dot"/> OSV DATABASE / LIVE ADVISORIES</div><h3>Package-level vulnerability feed</h3><p>Live advisories queried from OSV for Composer (Packagist) packages. Results are package-specific, not a complete search of every PHP advisory.</p></div>
                <button className="btn-secondary refresh-btn" onClick={() => void loadOsvFeed(osvPackage)} disabled={osvRefreshing}><RefreshCw size={15} className={osvRefreshing ? 'spin' : ''}/>{osvRefreshing ? 'Refreshing' : 'Refresh OSV'}</button>
              </div>
              <div className="osv-feed-meta"><span className={`feed-status ${osvState}`}><span className="live-dot"/>{osvState === 'loading' ? 'Connecting to OSV' : osvState === 'error' ? 'OSV unavailable' : 'OSV API connected'}</span><span><Clock3 size={13}/>{osvUpdated ? `Updated ${new Date(osvUpdated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Waiting for first sync'}</span><span>Query: {osvQueryLabel}</span></div>
              <form className="osv-search-row" onSubmit={event => { event.preventDefault(); void loadOsvFeed(osvPackage) }}>
                <label className="feed-search"><Search size={15}/><input value={osvPackage} onChange={event => setOsvPackage(event.target.value)} placeholder="Search Composer package e.g. laravel/framework"/></label>
                <button className="btn-primary" type="submit" disabled={osvRefreshing || !osvPackage.trim()}>Search package <ChevronRight size={14}/></button>
                <button className="btn-quiet" type="button" onClick={() => { setOsvPackage(''); void loadOsvFeed() }} disabled={osvRefreshing}>Popular packages</button>
              </form>
              {osvError && <div className={`feed-message ${osvState === 'error' ? 'error' : ''}`}><AlertTriangle size={15}/><span>{osvError}</span></div>}
              {osvState === 'loading' && !osvItems.length ? <div className="feed-empty"><RefreshCw size={18} className="spin"/><strong>Loading package advisories</strong><p>Querying OSV for published advisories. This may take a moment.</p></div> : osvItems.length ? <div className="osv-results">
                <div className="osv-results-summary"><strong>{osvItems.length} advisories</strong><span>Returned by OSV for {osvQueryLabel}</span></div>
                {osvItems.map(item => {
                  const scoreRaw = item.severity?.find(entry => entry.type?.toUpperCase().includes('CVSS'))?.score || ''
                  const scoreMatch = scoreRaw.match(/(?:^|\/)(\d+(?:\.\d+)?)$/)
                  const score = scoreMatch ? Number(scoreMatch[1]) : null
                  const severity = osvSeverity(item)
                  const affectedNames = Array.from(new Set((item.affected || []).map(affected => affected.package?.name).filter(Boolean)))
                  const summary = item.summary || item.details?.replace(/\s+/g, ' ').slice(0, 320) || 'No summary supplied by OSV.'
                  return <article className="osv-item" key={item.id}>
                    <div className="osv-item-main"><div className="threat-item-top"><a className="cve-title-button" href={`https://osv.dev/vulnerability/${encodeURIComponent(item.id)}`} target="_blank" rel="noreferrer">{item.id} <ArrowUpRight size={13}/></a><span className={`severity-pill ${severity.toLowerCase()}`}>{severity}{score !== null ? ` · ${score.toFixed(1)}` : ''}</span></div>
                    <p>{summary}</p><div className="threat-foot"><span>Published {item.published ? new Date(item.published).toLocaleDateString() : 'date unavailable'}</span><span>Packages: {affectedNames.slice(0, 3).join(', ') || 'see advisory'}</span><a href={`https://osv.dev/vulnerability/${encodeURIComponent(item.id)}`} target="_blank" rel="noreferrer">View advisory <ArrowUpRight size={12}/></a></div></div>
                  </article>
                })}
              </div> : <div className="feed-empty"><Search size={18}/><strong>No package advisories loaded</strong><p>Search for a specific Composer package name to query OSV directly.</p></div>}
              <div className="panel-note"><CircleHelp size={15}/><span>Data is fetched from the OSV API when this page loads, when refreshed, or after a package search. Coverage depends on the package names queried. Verify affected versions and remediation in the original advisory.</span></div>
            </section>
          </section>
          <div className="radar-layout">
          <section className="panel sources-panel">
            <div className="panel-header"><div><h3>Trusted source directory</h3><p>Start with the source, not the speculation.</p></div><span className="icon-box"><Radar size={18}/></span></div>
            <div className="source-list">{SOURCES.map((source, i) => <a className="source-row" key={source.name} href={source.url} target="_blank" rel="noreferrer">
              <span className="source-index">0{i + 1}</span><span className="source-icon"><source.icon size={18}/></span><span className="source-copy"><strong>{source.name}</strong><small>{source.detail}</small><em>{source.kind}</em></span><ArrowUpRight size={16} className="source-arrow"/>
            </a>)}</div>
            <div className="panel-note"><CircleHelp size={15}/><span>This MVP links to primary sources instead of presenting unverified claims as confirmed incidents.</span></div>
          </section>
          <section className="panel side-panel">
            <div className="panel-header"><div><h3>Signal integrity</h3><p>How to read security news</p></div><span className="icon-box"><BadgeCheck size={18}/></span></div>
            <div className="integrity-score"><div className="score-ring"><span>100<small>%</small></span></div><div><strong>Source-first policy</strong><p>Every claim should be traceable to a published advisory or record.</p></div></div>
            <div className="mini-divider"/>
            <div className="check-row"><Check size={15}/><span>Link to a primary source</span></div>
            <div className="check-row"><Check size={15}/><span>Confirm affected versions</span></div>
            <div className="check-row"><Check size={15}/><span>Check patch and release notes</span></div>
            <a className="text-link" href="https://www.php.net/releases/" target="_blank" rel="noreferrer">Review official PHP releases <ArrowUpRight size={14}/></a>
          </section>
          </div>
        </>}

        {selectedThreat && <div className="cve-modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) setSelectedThreat(null) }}>
          <section className="cve-modal" role="dialog" aria-modal="true" aria-labelledby="cve-modal-title">
            <div className="cve-modal-head"><div><span className="eyebrow left"><span className="live-dot"/> WATCHPHP / VULNERABILITY RECORD</span><h2 id="cve-modal-title">{selectedThreat.id}</h2></div><button className="modal-close" onClick={() => setSelectedThreat(null)} aria-label="Close vulnerability details">×</button></div>
            <div className="cve-modal-meta"><span className={`severity-pill ${selectedThreat.severity.toLowerCase()}`}>{selectedThreat.severity}{selectedThreat.score !== null ? ` · CVSS ${selectedThreat.score.toFixed(1)}` : ' · No CVSS score'}</span><span>Published {selectedThreat.published ? new Date(selectedThreat.published).toLocaleDateString() : 'date unavailable'}</span><span>Modified {selectedThreat.modified ? new Date(selectedThreat.modified).toLocaleDateString() : '—'}</span></div>
            <div className="cve-detail-section"><span className="cve-section-label">DESCRIPTION</span><p className="cve-description">{selectedThreat.description}</p></div>
            <div className="cve-detail-grid"><div className="cve-detail-section"><span className="cve-section-label">WEAKNESS / CWE</span>{selectedThreat.weaknesses.length ? <div className="cve-chip-list">{selectedThreat.weaknesses.map((weakness, index) => <span className="cve-chip" key={`${weakness}-${index}`}>{weakness}</span>)}</div> : <p className="cve-muted">No weakness classification included in this feed response.</p>}</div><div className="cve-detail-section"><span className="cve-section-label">SOURCE REFERENCES</span><p className="cve-muted">{selectedThreat.references.length} reference link{selectedThreat.references.length === 1 ? '' : 's'} included in this CVE record.</p></div></div>
            <div className="cve-detail-section"><span className="cve-section-label">AFFECTED PRODUCTS / VERSION MATCHES</span>{selectedThreat.affectedProducts.length ? <div className="affected-products">{selectedThreat.affectedProducts.slice(0, 20).map((product, index) => <article className="affected-product" key={`${product.vendor}-${product.product}-${index}`}><div><strong>{product.vendor} / {product.product}</strong><span className="affected-status">CVE product match marked vulnerable</span></div><div className="affected-versions">{product.versions?.map((version, versionIndex) => <span key={`${version.version}-${versionIndex}`}>{version.version || 'Version not specified'}{version.lessThan ? ` · ${version.lessThan}` : ''}</span>)}</div></article>)}</div> : <p className="cve-muted">This response did not include vulnerable CPE product matches. Check the source advisory for affected versions and fixes.</p>}<p className="cve-muted affected-note">CPE matches are taken from upstream CVE configurations; they may not provide complete fixed-version guidance.</p></div>
            <div className="cve-detail-section"><span className="cve-section-label">REFERENCES</span>{selectedThreat.references.length ? <div className="cve-reference-list">{selectedThreat.references.slice(0, 12).map((reference, index) => <a key={`${reference.url}-${index}`} href={reference.url} target="_blank" rel="noreferrer"><span>{reference.url.replace(/^https?:\/\//, '').slice(0, 100)}</span><ExternalLink size={13}/></a>)}</div> : <p className="cve-muted">No additional references included. Open the official record for the complete entry.</p>}</div>
            <div className="cve-modal-foot"><p>WATCHPHP displays published vulnerability data. Confirm affected products, version ranges, and remediation in the original advisory before taking action.</p><a className="btn-primary" href={selectedThreat.sourceUrl} target="_blank" rel="noreferrer">Open official CVE record <ArrowUpRight size={14}/></a></div>
          </section>
        </div>}

        {tab === 'scanner' && <section className="panel scanner-panel">
          <div className="panel-header"><div><h3>HTTP security header review</h3><p>Paste response headers from a system you own or are authorized to assess.</p></div><span className="icon-box"><ScanSearch size={18}/></span></div>
          <div className="notice"><LockKeyhole size={17}/><div><strong>Local-only analysis</strong><p>PHP WATCH does not request the target URL. Do not paste cookies, authorization headers, session tokens, or other secrets.</p></div></div>
          <div className="form-grid">
            <label className="field"><span>ASSESSMENT LABEL <small>Optional</small></span><input value={targetLabel} onChange={e => setTargetLabel(e.target.value)} placeholder="e.g. my-staging-site" maxLength={80}/></label>
            <div className="field"><span>INPUT TYPE</span><div className="readonly-field"><Terminal size={15}/> Raw HTTP response headers <span className="field-tag">TEXT</span></div></div>
          </div>
          <label className="field textarea-field"><span>RESPONSE HEADERS <small>Paste output from curl -sSI</small></span><textarea value={headers} onChange={e => {setHeaders(e.target.value); setRan(false)}} placeholder={'HTTP/2 200\\ncontent-type: text/html; charset=UTF-8\\nstrict-transport-security: max-age=31536000; includeSubDomains\\nx-content-type-options: nosniff'} rows={8}/></label>
          <div className="scanner-footer"><span className="input-count">{headers.length.toLocaleString()} characters · analyzed in browser</span><button className="btn-primary" disabled={!headers.trim()} onClick={runScan}><ScanSearch size={16}/> Analyze headers <ChevronRight size={15}/></button></div>
          {ran && <div className="results-block">
            <div className="results-head"><div><span className="eyebrow left">ASSESSMENT COMPLETE</span><h3>Header presence summary</h3></div><div className="result-score"><strong>{score}%</strong><small>coverage indicator</small></div></div>
            <div className="result-bar"><span style={{width: `${score}%`}}/></div>
            <div className="findings-list">{findings.map(f => <div className="finding" key={f.name}><span className={`finding-icon ${f.status === 'Present' ? 'good' : f.severity === 'warn' ? 'warn' : 'info'}`}>{f.status === 'Present' ? <Check size={15}/> : <ShieldAlert size={15}/>}</span><div className="finding-copy"><strong>{f.name}</strong><small>{f.detail}</small></div><span className={`finding-status ${f.status === 'Present' ? 'good-text' : ''}`}>{f.status}</span></div>)}</div>
            <div className="disclaimer"><CircleHelp size={15}/><span>This is a lightweight presence check, not a full audit. Missing headers are not proof of a vulnerability; verify values and application context.</span></div>
            <button className="btn-secondary" onClick={() => setTab('report')}><FileSearch size={16}/> View shareable report <ChevronRight size={15}/></button>
          </div>}
        </section>}

        {tab === 'report' && <section className="panel report-panel">
          <div className="panel-header"><div><h3>Shareable assessment</h3><p>Review the generated text before copying it anywhere public.</p></div><span className="icon-box"><FileSearch size={18}/></span></div>
          {!ran ? <div className="empty-state"><FileSearch size={28}/><strong>No report yet</strong><p>Run a Safe Scanner header review to generate a report.</p><button className="btn-primary" onClick={() => setTab('scanner')}>Open Safe Scanner <ChevronRight size={15}/></button></div> : <>
            <div className="report-banner"><div className="report-mark"><ShieldCheck size={25}/></div><div><span className="eyebrow left">PHP WATCH / SECURITY REVIEW</span><h3>{targetLabel.trim() || 'Unlabelled assessment'}</h3><p>Header presence review · Generated locally</p></div><span className="report-badge">MVP REPORT</span></div>
            <div className="report-stats"><div><small>HEADERS DETECTED</small><strong>{present}<span>/6</span></strong></div><div><small>COVERAGE INDICATOR</small><strong>{score}<span>%</span></strong></div><div><small>REMOTE REQUESTS</small><strong>0</strong></div></div>
            <pre className="report-preview">{reportText}</pre>
            <div className="report-actions"><button className="btn-primary" onClick={copyReport}>{copied ? <Check size={16}/> : <Copy size={16}/>} {copied ? 'Copied to clipboard' : 'Copy report text'}</button><button className="btn-secondary" onClick={() => window.open('https://x.com/intent/post?text=' + encodeURIComponent('I reviewed HTTP security headers with PHP WATCH — a source-first, local-only PHP security toolkit. ' + score + '% header presence indicator. Missing headers are not proof of a vulnerability. #PHP #AppSec'), '_blank', 'noopener,noreferrer')}>Share on X <ArrowUpRight size={15}/></button></div>
            <div className="disclaimer"><CircleHelp size={15}/><span>Review and redact labels before sharing. The score indicates header presence only; it is not a security rating or proof that a system is safe.</span></div>
          </>}
        </section>}

        <footer className="footer"><span>PHP WATCH <span className="green">/</span> COMMUNITY SECURITY TOOLKIT</span><span>NOT A FULL SECURITY AUDIT <span className="footer-dot">•</span> NOT AFFILIATED WITH PHP.NET</span></footer>
      </div>
    </main>
  </div>
}

function Metric({ icon, label, value, note }: { icon: React.ReactNode; label: string; value: string; note: string }) {
  return <div className="metric-card"><div className="metric-top"><span className="metric-icon">{icon}</span><span>{label}</span></div><strong>{value}</strong><small>{note}</small></div>
}

export default App
