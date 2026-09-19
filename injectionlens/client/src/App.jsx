import React, { useEffect, useMemo, useRef, useState } from 'react'

const LEVEL_COLOR = {
  critical: '#ff4d6d',
  high: '#ff8f3d',
  medium: '#ffd43d',
  low: '#69db7c',
  info: '#748ffc',
}

const SIGNAL_LABEL = {
  'html-comment': 'HTML comment',
  'zero-width-chars': 'Zero-width chars',
  'render-hidden': 'Hidden after render',
  'ai-visible-human-invisible': 'AI-visible / human-invisible',
  'raw-only': 'Raw-source only',
  'hidden-in-source': 'Hidden in source markup',
  'meta-tag': 'Meta tag',
  'reader-excludes': 'Excluded by Readability',
  'quoted-context': 'Quoted/educational context',
  'ua-cloaking': 'UA cloaking detected',
  'decoded-invisible-text': 'Decoded invisible text',
  'addressed-to-ai': 'Addressed to AI',
}

export default function App() {
  const [fixtures, setFixtures] = useState([])
  const [capabilities, setCapabilities] = useState([])
  const [target, setTarget] = useState('/fixtures/attack-hidden-displaynone.html')
  const [capability, setCapability] = useState('summary-only')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [tab, setTab] = useState('human')

  useEffect(() => {
    fetch('/api/fixtures').then((r) => r.json()).then((d) => setFixtures(d.fixtures || [])).catch(() => {})
    fetch('/api/capabilities').then((r) => r.json()).then((d) => setCapabilities(d || [])).catch(() => {})
  }, [])

  const analyze = async () => {
    setLoading(true); setError(null); setResult(null); setSelected(null)
    try {
      const r = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, capability }),
      })
      const data = await r.json()
      if (!r.ok) throw new Error(data.error || 'analysis failed')
      setResult(data)
      if (data.findings.length) setSelected(data.findings[0].id)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setLoading(false)
    }
  }

  const selFinding = useMemo(
    () => result?.findings.find((f) => f.id === selected) || null,
    [result, selected]
  )

  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="logo">◉</span>
          <h1>InjectionLens</h1>
        </div>
        <p className="tagline">See what the AI sees that you do not — cross-ingestion prompt-injection forensics</p>
      </header>

      <section className="controls card">
        <div className="row">
          <label>Target page</label>
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            {fixtures.map((f) => <option key={f} value={f}>{f.replace('/fixtures/', '')}</option>)}
            <option value="__custom">— paste a URL below —</option>
          </select>
          {target === '__custom' && (
            <input
              className="url-input"
              placeholder="https://example.com/page"
              onBlur={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setTarget(e.target.value)}
            />
          )}
        </div>
        <div className="row">
          <label>Agent capability template</label>
          <div className="caps">
            {capabilities.map((c) => (
              <button
                key={c.key}
                className={'cap' + (capability === c.key ? ' active' : '')}
                title={c.blurb}
                onClick={() => setCapability(c.key)}
              >
                {c.label}
              </button>
            ))}
          </div>
          <button className="analyze" onClick={analyze} disabled={loading}>
            {loading ? 'Analyzing 4 pipelines…' : '▶ Analyze'}
          </button>
        </div>
        {error && <div className="error">⚠ {error}</div>}
      </section>

      {result && (
        <>
          {result.cloak && (
            <div className="cloak-banner">
              🕵️ <b>UA cloaking detected:</b> the server served {result.cloak.aiBytes} B to {result.cloak.bot} vs{' '}
              {result.cloak.humanBytes} B to a browser UA, including {result.cloak.aiOnlySegments.length} AI-only segment(s).
            </div>
          )}

          <section className="summary card">
            <div className="stat"><b>{result.pageTitle || '(untitled)'}</b><span>{result.url}</span></div>
            <div className="chips">
              {Object.entries(result.levelCount).map(([lv, n]) => (
                <span key={lv} className="chip" style={{ borderColor: LEVEL_COLOR[lv], color: LEVEL_COLOR[lv] }}>
                  {lv} {n}
                </span>
              ))}
            </div>
            <div className="stat small">
              <span>HTTP source: {result.stats.httpSourceItems} segments</span>
              <span>Rendered DOM: {result.stats.renderedItems}</span>
              <span>Reader/Markdown: {result.stats.readerSegments}</span>
              <span>A11y tree: {result.stats.a11yNodes} nodes</span>
              <span>{result.elapsedMs} ms</span>
            </div>
          </section>

          <main className="grid">
            <section className="findings card">
              <h2>Findings ({result.findings.length})</h2>
              {result.findings.length === 0 && <p className="muted">No suspicious cross-pipeline differences found.</p>}
              {result.findings.map((f) => (
                <article
                  key={f.id}
                  className={'finding' + (selected === f.id ? ' selected' : '')}
                  onClick={() => setSelected(f.id)}
                >
                  <div className="finding-head">
                    <span className="badge" style={{ background: LEVEL_COLOR[f.impact.level] }}>{f.impact.level}</span>
                    <span className="f-id">{f.id}</span>
                    {f.instruction && <span className="instr">⚔ {f.instruction}</span>}
                    <span className={'vis ' + (f.humanVisible ? 'v-yes' : 'v-no')}>
                      {f.humanVisible ? '👁 human-visible' : '🚫 human-invisible'}
                    </span>
                  </div>
                  <p className="excerpt">“{f.excerpt}”</p>
                  {((f.intents && f.intents.length) || f.addressedToAI || f.discounted) && (
                    <div className="finding-chips">
                      {(f.intents || []).map((it) => <span key={it} className="intent-chip">{it}</span>)}
                      {f.addressedToAI && <span className="meta-chip">addressed to AI</span>}
                      {f.discounted && <span className="meta-chip">discounted: quoted in visible code</span>}
                    </div>
                  )}
                  <div className="ai-profiles">
                    ingested by: {f.aiProfiles.map((p) => <code key={p}>{p}</code>)}
                  </div>
                  <ul className="signals">
                    {f.signals.map((s, i) => (
                      <li key={i}><b>[{SIGNAL_LABEL[s.type] || s.type}]</b> {s.detail}</li>
                    ))}
                  </ul>
                  {selected === f.id && (
                    <p className="impact"><b>Impact under “{result.capabilityLabel}”:</b> {f.impact.explanation}</p>
                  )}
                </article>
              ))}
            </section>

            <section className="viewer card">
              <div className="tabs">
                <button className={tab === 'human' ? 'active' : ''} onClick={() => setTab('human')}>Human view (rendered)</button>
                <button className={tab === 'reader' ? 'active' : ''} onClick={() => setTab('reader')}>Reader/Markdown (agent view)</button>
              </div>
              {tab === 'human' ? (
                <HumanView html={result.humanHtml} nodeRef={selFinding?.nodeRef} />
              ) : (
                <pre className="markdown-view">{result.readerMarkdown || '(Readability produced no article)'}</pre>
              )}
            </section>
          </main>

          <section className="matrix card">
            <h2>Ingestion matrix — which pipeline saw what</h2>
            <table>
              <thead>
                <tr>
                  <th>Segment</th>
                  <th>Human view</th>
                  <th>HTTP source</th>
                  <th>Rendered DOM</th>
                  <th>Reader/Markdown</th>
                  <th>A11y tree</th>
                  <th>Signal</th>
                </tr>
              </thead>
              <tbody>
                {result.matrix.map((row) => (
                  <tr key={row.key} className={row.findingId ? 'has-finding' : ''} onClick={() => row.findingId && setSelected(row.findingId)}>
                    <td className="seg" title={row.key}>{row.excerpt.slice(0, 90)}{row.key.length > 90 ? '…' : ''}</td>
                    <td>{row.humanVisible ? <span className="yes">visible</span> : <span className="no">invisible</span>}</td>
                    <td>{row.httpSource ? <span className="yes">✓</span> : <span className="muted">—</span>}</td>
                    <td>{row.renderedDom === 'visible' ? <span className="yes">visible</span> : row.renderedDom === 'hidden' ? <span className="warn">hidden</span> : <span className="muted">—</span>}</td>
                    <td>{row.readerMarkdown ? <span className="yes">✓</span> : <span className="muted">—</span>}</td>
                    <td>{row.accessibilityTree ? <span className="yes">✓</span> : <span className="muted">—</span>}</td>
                    <td>{row.findingId ? <span className="badge mini" style={{ background: LEVEL_COLOR[result.findings.find((f) => f.id === row.findingId)?.impact.level] }}>{row.findingId}</span> : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}

      <footer>
        InjectionLens · TLN Cybersecurity Challenge 2026 · analysis runs locally; pages are fetched read-only ·
        InjectionLens reduces and surfaces risk — no scanner can “solve” prompt injection.
      </footer>
    </div>
  )
}

function HumanView({ html, nodeRef }) {
  const ref = useRef(null)
  const srcDoc = useMemo(() => {
    if (!html) return ''
    const highlight = nodeRef
      ? `<style>[data-ilid]{transition:outline .2s}[data-ilid="${nodeRef}"]{outline:3px solid #ff4d6d !important;background:rgba(255,77,109,.18) !important;box-shadow:0 0 0 6px rgba(255,77,109,.15)}</style>`
      : '<style></style>'
    return html.replace('</head>', highlight + '</head>')
  }, [html, nodeRef])

  useEffect(() => {
    if (ref.current && nodeRef) {
      const doc = ref.current.contentDocument
      const el = doc?.querySelector(`[data-ilid="${nodeRef}"]`)
      if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' })
    }
  }, [srcDoc, nodeRef])

  return <iframe ref={ref} className="human-frame" sandbox="" title="human view" srcDoc={srcDoc} />
}
