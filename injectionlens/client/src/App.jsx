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
  'near-invisible': 'Near-invisible to humans',
  'attribute-value': 'Attribute value',
  'data-attribute': 'data-* attribute',
  'document-title': 'Document title',
  'inert-template': 'Inert <template>',
  'noscript-content': '<noscript> content',
  'invisible-unicode': 'Invisible Unicode',
  'jsonld': 'JSON-LD string',
  'ai-summary-link': 'AI-summary link',
  'recommendation-manipulation': 'Recommendation manipulation',
  'benign-summary-request': 'Benign summary request',
  'url-fragment': 'URL fragment',
  'embedded-destination': 'Named destination (not contacted)',
}

const DELIVERY_LABEL = {
  visible: 'visible page text',
  'css-hidden': 'CSS-hidden element',
  'near-invisible': 'near-invisible text (1px / low opacity)',
  comment: 'HTML comment',
  attribute: 'HTML attribute',
  meta: 'meta tag',
  jsonld: 'JSON-LD structured data',
  'ai-only': 'served only to an AI crawler User-Agent',
  'ai-link-prompt': 'pre-filled prompt in a link query string',
  'url-fragment': 'URL fragment (never sent to the server)',
}

// The four ingestion pipelines, in the order the report reads them. A pipeline
// that did not observe an instruction is reported as "no instruction observed",
// never as "safe".
const PIPELINES = [
  { id: 'http-source', label: 'HTTP source', stat: 'httpSourceItems' },
  { id: 'rendered-dom', label: 'Rendered DOM', stat: 'renderedItems' },
  { id: 'reader-markdown', label: 'Reader/Markdown', stat: 'readerSegments' },
  { id: 'accessibility-tree', label: 'Accessibility tree', stat: 'a11yNodes' },
]

const LEVEL_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

function highestLevel(levelCount) {
  let best = 'info'
  for (const level of Object.keys(LEVEL_RANK)) {
    if ((levelCount?.[level] || 0) > 0) best = level
  }
  return best
}

/** The empty demo scenario: the local scam-ad-review replica under decision-agent. */
const DEMO = {
  target: '/fixtures/replica-scam-ad-review.html',
  capability: 'decision-agent',
  label: 'Unit 42 scam-ad review page, seen by a decision agent',
}

export default function App() {
  const [fixtures, setFixtures] = useState([])
  const [capabilities, setCapabilities] = useState([])
  const [target, setTarget] = useState(DEMO.target)
  const [capability, setCapability] = useState(DEMO.capability)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [tab, setTab] = useState('human')

  useEffect(() => {
    fetch('/api/fixtures').then((r) => r.json()).then((d) => setFixtures(d.fixtures || [])).catch(() => {})
    fetch('/api/capabilities').then((r) => r.json()).then((d) => setCapabilities(d || [])).catch(() => {})
  }, [])

  const analyze = async (override) => {
    const nextTarget = (override && override.target) || target
    const nextCapability = (override && override.capability) || capability
    setLoading(true); setError(null); setResult(null); setSelected(null)
    try {
      const r = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: nextTarget, capability: nextCapability }),
      })
      const data = await r.json()
      if (!r.ok) {
        // A blocked or refused target is a first-class result, never a green one.
        const kind = data.blocked ? 'blocked' : 'failure'
        throw Object.assign(new Error(data.error || 'analysis failed'), { kind, code: data.code })
      }
      setResult(data)
      setCapability(nextCapability)
      if (data.findings.length) setSelected(data.findings[0].id)
    } catch (e) {
      setError({ kind: e.kind || 'failure', message: String(e.message || e), code: e.code || null })
    } finally {
      setLoading(false)
    }
  }

  // Capability switching re-runs the real analysis. Nothing here is a canned
  // result: the levels, intents and explanations all come from the API.
  const switchCapability = (key) => {
    if (key === capability && result) return
    analyze({ capability: key })
  }

  const runDemo = () => {
    setTarget(DEMO.target)
    analyze({ target: DEMO.target, capability: DEMO.capability })
  }

  const selFinding = useMemo(
    () => result?.findings.find((f) => f.id === selected) || null,
    [result, selected]
  )

  const observedPipelines = useMemo(() => {
    if (!result) return {}
    const observed = {}
    for (const pipeline of PIPELINES) observed[pipeline.id] = { items: 0, findings: 0 }
    for (const row of result.matrix || []) {
      if (row.httpSource) observed['http-source'].items += 1
      if (row.renderedDom && row.renderedDom !== 'absent') observed['rendered-dom'].items += 1
      if (row.readerMarkdown) observed['reader-markdown'].items += 1
      if (row.accessibilityTree) observed['accessibility-tree'].items += 1
    }
    for (const finding of result.findings || []) {
      for (const profile of finding.aiProfiles || []) {
        if (observed[profile]) observed[profile].findings += 1
      }
    }
    // Channel inspections are not ingestion pipelines; they are reported apart.
    for (const item of result.inspections || []) {
      observed[item.channel] = observed[item.channel] || { items: 0, findings: 0 }
      observed[item.channel].findings += 1
    }
    return observed
  }, [result])

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
        <div className="row demo-row">
          <button className="demo" onClick={runDemo} disabled={loading}>
            ▶ Run the demo
          </button>
          <span className="demo-hint">
            One click: <b>{DEMO.label}</b> ({DEMO.target.replace('/fixtures/', '')}, capability <code>{DEMO.capability}</code>).
            No URL to type. Every number below comes from this live analysis.
          </span>
        </div>
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
                onClick={() => switchCapability(c.key)}
                disabled={loading}
              >
                {c.label}
              </button>
            ))}
          </div>
          <button className="analyze" onClick={() => analyze()} disabled={loading}>
            {loading ? 'Analyzing 4 pipelines…' : '▶ Analyze'}
          </button>
        </div>
        {loading && (
          <div className="loading" role="status">
            <span className="spinner" aria-hidden="true" /> Reading the page through four ingestion pipelines
            and probing the configured AI-agent User-Agents…
          </div>
        )}
        {error && (
          <div className={'error ' + (error.kind === 'blocked' ? 'blocked' : 'failed')}>
            <b>{error.kind === 'blocked' ? '⛔ Blocked — nothing was analysed.' : '⚠ Analysis failed — the result below would be incomplete, so none is shown.'}</b>
            <div className="error-detail">{error.message}</div>
            {error.kind === 'blocked' && (
              <div className="error-hint">
                External analysis is <b>disabled by default</b>. Only the built-in test pages are reachable:
                the network guard refuses loopback, private, link-local and metadata addresses, and any host
                that is not explicitly allowlisted. To analyse another host, name it in
                <code>INJECTIONLENS_ALLOWED_HOSTS</code> and restart the API. Crawler-User-Agent probing has a
                <b> separate</b> boundary: it stays limited to the test pages unless a host is listed in
                <code>INJECTIONLENS_UA_PROBE_ALLOWLIST</code>.
              </div>
            )}
          </div>
        )}
      </section>

      {result && (
        <>
          {/* ---------- the five questions, answered at a glance ---------- */}
          <section className="verdict card">
            <div className="verdict-main">
              <span className="verdict-badge" style={{ background: LEVEL_COLOR[highestLevel(result.levelCount)] }}>
                {highestLevel(result.levelCount)}
              </span>
              <div>
                <b className="verdict-title">Highest risk level on this page</b>
                <div className="muted small">
                  rule-based tier from the intent and the selected capability — not a measured probability
                </div>
              </div>
              <div className="verdict-stats">
                <div className="stat"><b>{result.findings.length}</b><span>findings</span></div>
                <div className="stat"><b>{[...new Set((result.findings || []).flatMap((f) => f.intents || []))].length}</b><span>intents</span></div>
                <div className="stat"><b>{result.capability}</b><span>capability</span></div>
                <div className="stat"><b>{result.levelCount.high + result.levelCount.critical}</b><span>high or above</span></div>
              </div>
            </div>
            <div className="verdict-grid">
              <div>
                <span className="field-label">What was detected</span>
                <div className="chips">
                  {[...new Set((result.findings || []).flatMap((f) => f.intents || []))].map((intent) => (
                    <span key={intent} className="intent-chip">{intent}</span>
                  ))}
                  {result.findings.length === 0 && <span className="muted">nothing instruction-like</span>}
                </div>
              </div>
              <div>
                <span className="field-label">Where it was found</span>
                <div className="chips">
                  {[...new Set((result.findings || []).filter((f) => !f.channel).map((f) => f.delivery))].map((delivery) => (
                    <span key={delivery} className="meta-chip">{DELIVERY_LABEL[delivery] || delivery}</span>
                  ))}
                  {[...new Set((result.inspections || []).map((item) => item.delivery))].map((delivery) => (
                    <span key={delivery} className="meta-chip">{DELIVERY_LABEL[delivery] || delivery}</span>
                  ))}
                </div>
              </div>
              <div className="span-2">
                <span className="field-label">Which ingestion pipelines observed it</span>
                <div className="pipeline-grid">
                  {PIPELINES.map((pipeline) => {
                    const seen = observedPipelines[pipeline.id] || { items: 0, findings: 0 }
                    const count = result.stats[pipeline.stat] || 0
                    return (
                      <div key={pipeline.id} className={'pipeline-cell' + (seen.findings > 0 ? ' hit' : '')}>
                        <b>{pipeline.label}</b>
                        <span>{count} item{count === 1 ? '' : 's'} read</span>
                        <span className={seen.findings > 0 ? 'v-no' : 'muted'}>
                          {seen.findings > 0
                            ? `${seen.findings} instruction finding(s)`
                            : 'no instruction observed'}
                        </span>
                      </div>
                    )
                  })}
                </div>
                <p className="muted small">
                  "No instruction observed" means this pipeline did not surface an instruction in this run.
                  It is <b>not</b> a statement that the pipeline is safe — a pipeline can miss text it did read.
                </p>
              </div>
              {((result.inspections || []).length > 0 || result.stats.assistantLinks > 0) && (
                <div className="span-2">
                  <span className="field-label">Channel checks (not ingestion pipelines)</span>
                  {(result.inspections || []).map((item, index) => (
                    <div key={`${item.channel}-${index}`} className="channel-row">
                      <span className="intent-chip">{item.channel}</span>
                      <span className={`badge mini`} style={{ background: LEVEL_COLOR[item.level] }}>{item.level}</span>
                      <span className="channel-text">{item.text}</span>
                      {item.classification?.benignSummaryRequest && (
                        <span className="meta-chip">classified benign: plain summary request</span>
                      )}
                      {item.classification?.manipulative && (
                        <span className="meta-chip">manipulation markers: {item.classification.recommendationMarkers.join(', ')}</span>
                      )}
                    </div>
                  ))}
                  {(result.inspections || []).length === 0 && (
                    <p className="muted small">
                      {result.stats.assistantLinks} assistant link(s) found, none carrying a pre-filled prompt;
                      no URL fragment on this target.
                    </p>
                  )}
                </div>
              )}
            </div>
          </section>

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

          {/* A partial pipeline is stated plainly: missing evidence is not the same as no risk. */}
          {(result.stats.renderedItems === 0 || result.stats.a11yNodes === 0) && (
            <div className="partial-banner">
              ⚠ <b>Partial analysis:</b> the rendered-DOM / accessibility pipelines returned no data
              {result.stats.renderedItems === 0 ? ' (rendered DOM empty)' : ''}
              {result.stats.a11yNodes === 0 ? ' (no accessibility nodes)' : ''}
              — a headless browser may be unavailable on this machine. Findings below cover only the
              pipelines that did run, so the risk picture is incomplete, not absent.
            </div>
          )}

          {Array.isArray(result.uaProbe) && result.uaProbe.some((p) => p.token === null) && (
            <div className="partial-banner">
              ⓘ <b>Crawler-User-Agent probe not run for this target.</b>{' '}
              {(result.uaProbe.find((p) => p.token === null) || {}).status} UA probing is only a lower bound:
              cloaking driven by behavioural fingerprinting is not covered by this tool.
            </div>
          )}

          {result.cloak && (
            <div className="cloak-banner">
              🕵️ <b>UA cloaking detected:</b> the server served {result.cloak.aiBytes} B to {result.cloak.bot} vs{' '}
              {result.cloak.humanBytes} B to a browser UA, including {result.cloak.aiOnlySegments.length} AI-only segment(s).
              {' '}Triggering token: <code>{result.cloak.triggerToken}</code> (actual User-Agent sent: <code>{result.cloak.uaUsed}</code>, category: {result.cloak.category}).
              {(result.uaProbe || []).filter((p) => p.status === 'probed').length > 0 && (
                <> Probed {(result.uaProbe || []).filter((p) => p.status === 'probed').length} of {(result.uaProbe || []).length} configured tokens.</>
              )}
            </div>
          )}

          {result.stats.blockedSubrequests > 0 && (
            <div className="partial-banner">
              🛡 <b>{result.stats.blockedSubrequests} browser request(s) blocked</b> by the network boundary while
              rendering this page (third-party or non-public destinations). The rendered view may differ from a
              normal browser because those requests never left the machine.
            </div>
          )}

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
                    observed by: {f.aiProfiles.map((p) => <code key={p}>{p}</code>)}
                    {f.delivery && <span className="delivery"> via {DELIVERY_LABEL[f.delivery] || f.delivery}</span>}
                  </div>
                  {selected === f.id && (
                    <div className="evidence">
                      <div className="evidence-row">
                        <span className="field-label">Original instruction evidence</span>
                        <pre className="evidence-pre">{f.originalText || f.fullText || f.excerpt}</pre>
                      </div>
                      {f.normalizedText && f.normalizedText !== (f.originalText || f.fullText) && (
                        <div className="evidence-row">
                          <span className="field-label">Normalized comparison form</span>
                          <pre className="evidence-pre">{f.normalizedText}</pre>
                        </div>
                      )}
                      {(f.occurrences || []).some((o) => o.decodedText) && (
                        <div className="evidence-row">
                          <span className="field-label">Decoded from an invisible channel</span>
                          <pre className="evidence-pre">
                            {(f.occurrences || []).map((o) => o.decodedText).filter(Boolean).join('\n')}
                          </pre>
                        </div>
                      )}
                      {f.channelEvidence && (
                        <div className="evidence-row">
                          <span className="field-label">
                            {f.channel === 'url-fragment' ? 'URL fragment' : 'Assistant link'} evidence
                          </span>
                          <pre className="evidence-pre">{[
                            `source URL : ${f.channelEvidence.sourceUrl}`,
                            f.channelEvidence.host ? `host       : ${f.channelEvidence.host}` : null,
                            f.channelEvidence.param ? `parameter  : ${f.channelEvidence.param}` : null,
                            f.channelEvidence.rawValue ? `raw value  : ${f.channelEvidence.rawValue}` : null,
                            `decoded    : ${f.channelEvidence.decoded}`,
                            f.channelEvidence.nestedParams ? `nested     : ${JSON.stringify(f.channelEvidence.nestedParams)}` : null,
                            f.channelEvidence.sentToServer === false ? 'sent to server: no (a fragment never is)' : null,
                            f.channelEvidence.embeddedUrls?.length
                              ? `names      : ${f.channelEvidence.embeddedUrls.join(', ')} (recorded, never requested)`
                              : null,
                          ].filter(Boolean).join('\n')}</pre>
                        </div>
                      )}
                      <div className="evidence-row">
                        <span className="field-label">Where the pipelines saw it</span>
                        <ul className="occurrence-list">
                          {(f.occurrences || []).map((o, i) => (
                            <li key={i}>
                              <code>{o.pipeline}</code>
                              <span className="muted"> / {o.extractionKind}{o.path ? ` / ${o.path}` : ''}</span>
                            </li>
                          ))}
                          {(f.occurrences || []).length === 0 && <li className="muted">no per-pipeline occurrence recorded</li>}
                        </ul>
                      </div>
                    </div>
                  )}
                  <ul className="signals">
                    {f.signals.map((s, i) => (
                      <li key={i}><b>[{SIGNAL_LABEL[s.type] || s.type}]</b> {s.detail}</li>
                    ))}
                  </ul>
                  {selected === f.id && (
                    <p className="impact">
                      <b>Why this level under “{result.capabilityLabel}”:</b> {f.impact.explanation}
                    </p>
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
        InjectionLens · TLN Cybersecurity Challenge 2026 · analysis runs locally; pages are fetched read-only.
        <br />
        External analysis is <b>disabled by default</b> — a host must be allowlisted, and loopback, private,
        link-local and cloud-metadata addresses are always refused. Crawler-User-Agent probing has a narrower,
        separate permission boundary and never runs against third-party hosts.
        <br />
        Channel checks (P1): a "summarize with AI" link's pre-filled prompt and a URL fragment are decoded and
        analysed locally. InjectionLens never opens, submits to, or follows an assistant link, and it never
        requests a destination named inside a decoded prompt.
        <br />
        Hidden content is <b>surfaced, not judged</b>: invisible or near-invisible text is reported as evidence,
        not as proof of malice. The UA probe is only a <b>lower bound</b> — cloaking driven by behavioural
        fingerprinting is not detected, screenshot/OCR agents are not covered, and DNS rebinding is not fully
        solved because the validated address is not pinned to the final connection.
        <br />
        Timed snapshots and behavioural-fingerprint cloaking are <b>not implemented</b>; the UA probe is a lower
        bound only. Real-world benign-page false-positive rate: <b>NOT RUN</b> (no approved host list).
        Detection rates are measured on the external attack library and reported as numerators and denominators,
        never as a single accuracy figure.
        <br />
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
