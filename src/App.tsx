import { useMemo, useState } from 'react'
import {
  Activity, ArrowUpRight, BadgeCheck, BookOpen, Check, ChevronRight, CircleHelp,
  Copy, ExternalLink, FileSearch, Github, Globe2, LockKeyhole, Radar, ScanSearch,
  Shield, ShieldAlert, ShieldCheck, Terminal, Zap
} from 'lucide-react'

type Tab = 'radar' | 'scanner' | 'report'
type Finding = { name: string; status: 'Present' | 'Not detected' | 'Review'; detail: string; severity: 'good' | 'warn' | 'info' }

const SOURCES = [
  { name: 'PHP Security Advisories', kind: 'Primary source', detail: 'Official PHP security announcements and release information.', url: 'https://www.php.net/releases/', icon: ShieldCheck },
  { name: 'National Vulnerability Database', kind: 'Vulnerability database', detail: 'Search CVE records and published vulnerability references.', url: 'https://nvd.nist.gov/vuln/search/results?query=PHP&search_type=all', icon: Radar },
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

function App() {
  const [tab, setTab] = useState<Tab>('radar')
  const [headers, setHeaders] = useState('')
  const [targetLabel, setTargetLabel] = useState('')
  const [ran, setRan] = useState(false)
  const [copied, setCopied] = useState(false)
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

        {tab === 'radar' && <div className="radar-layout">
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
