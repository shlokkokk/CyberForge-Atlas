import { useEffect, useMemo, useState, useCallback, useRef, memo } from 'react'
import Fuse from 'fuse.js'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import './App.css'

/* =========================================
   TAB CONFIGURATION
   ========================================= */
const TABS = [
  { key: 'definition', label: 'Definition', icon: '◈' },
  { key: 'payloads', label: 'Payloads', icon: '⚡' },
  { key: 'howTo', label: 'How-To', icon: '▶' },
  { key: 'examples', label: 'Examples', icon: '◉' },
  { key: 'labs', label: 'Labs', icon: '⬡' },
  { key: 'tools', label: 'Tools', icon: '⚙' },
  { key: 'references', label: 'Refs', icon: '◇' },
  { key: 'books', label: 'Books', icon: '▤' },
  { key: 'mitigation', label: 'Mitigation', icon: '▣' },
  { key: 'knowledge', label: 'Other', icon: '∞' },
  { key: 'sources', label: 'Raw Files', icon: '⊞' },
]

/* =========================================
   HELPERS
   ========================================= */
function mdComponents() {
  return {
    a: ({ ...props }) => <a target="_blank" rel="noreferrer" {...props} />,
  }
}

function buildTabCounts(attack) {
  if (!attack) return {}
  return {
    definition: attack.sections.definition.length,
    payloads: attack.sections.payloads.length,
    howTo: attack.sections.howTo.length,
    knowledge: attack.sections.other.length,
    examples: attack.sections.examples.length,
    labs: attack.sections.labs.length,
    tools: attack.sections.tools.length,
    references: attack.sections.references.length,
    books: attack.sections.books.length,
    mitigation: attack.sections.mitigation.length,
    sources: attack.documents.length,
  }
}

/**
 * Smartly formats content: if it's raw text/payloads (no markdown headers, many lines),
 * wrap it in a code block to preserve structure and give it a terminal look.
 */
function FormatContent({ content, sourcePath = '' }) {
  const isRaw = useMemo(() => {
    if (sourcePath.endsWith('.txt') || sourcePath.endsWith('.py') || sourcePath.endsWith('.sh')) return true
    
    // If it has markdown headers or code blocks, it's already structured
    const hasHeaders = /^#{1,6}\s/m.test(content)
    const hasCodeBlocks = /```/.test(content)
    if (hasHeaders || hasCodeBlocks) return false

    // If it has markdown lists or links, it should be rendered as markdown
    const hasLists = /^[\s]*(\*|-|\d+\.)\s/m.test(content)
    const hasLinks = /\[.+\]\(.+\)/.test(content)
    if (hasLists || hasLinks) return false

    // If it has no headers/lists/links but many lines, it's likely a raw payload list
    const lineCount = (content.match(/\n/g) || []).length
    return lineCount > 3
  }, [content, sourcePath])

  const processedContent = isRaw ? `\`\`\`text\n${content}\n\`\`\`` : content

  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents()}>
      {processedContent}
    </ReactMarkdown>
  )
}
const MemoizedFormatContent = memo(FormatContent)


/* =========================================
   SECTION ITEMS
   ========================================= */
function SectionItems({ items }) {
  const [limit, setLimit] = useState(15)
  
  if (!items || items.length === 0) {
    return (
      <div className="empty-note">
        <p>No data available for this section.</p>
      </div>
    )
  }

  const visibleItems = items.slice(0, limit)
  const hasMore = items.length > limit

  return (
    <div className="entry-grid">
      {visibleItems.map((item, idx) => (
        <article className="entry-card" key={`${item.sourcePath}-${item.heading}-${idx}`}>
          <header>
            <strong>{item.heading}</strong>
            <span>{item.sourcePath}</span>
          </header>
          <MemoizedFormatContent content={item.content} sourcePath={item.sourcePath} />
        </article>
      ))}
      {hasMore && (
        <button className="loadMoreBtn" onClick={() => setLimit(prev => prev + 30)}>
          Load More Results ({items.length - limit} remaining)
        </button>
      )}
    </div>
  )
}


/* =========================================
   SOURCE ITEMS
   ========================================= */
function SourceItems({ items }) {
  const [limit, setLimit] = useState(15)
  if (!items || items.length === 0) {
    return <div className="empty-note"><p>No raw source files available.</p></div>
  }

  const visibleItems = items.slice(0, limit)
  const hasMore = items.length > limit

  return (
    <div className="entry-grid">
      {visibleItems.map((item, idx) => (
        <article className="entry-card" key={`${item.relativePath}-${idx}`}>
          <header>
            <strong>{item.title}</strong>
            <span>{item.relativePath}</span>
          </header>
          <MemoizedFormatContent content={item.content} sourcePath={item.relativePath} />
        </article>
      ))}
      {hasMore && (
        <button className="loadMoreBtn" onClick={() => setLimit(prev => prev + 30)}>
          Load More Files ({items.length - limit} remaining)
        </button>
      )}
    </div>
  )
}

const AttackListItem = memo(({ attack, isActive, onClick }) => (
  <button
    type="button"
    className={`attackItem ${isActive ? 'active' : ''}`}
    onClick={onClick}
  >
    <strong>{attack.name}</strong>
    <p>{attack.summary}</p>
    <div className="meta">
      <span>{attack.stats.documents} files</span>
      <span>{attack.stats.totalLines.toLocaleString()} LOC</span>
    </div>
  </button>
))


/* =========================================
   MAIN APP
   ========================================= */
function App() {
  const [database, setDatabase] = useState(null)
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [selectedTab, setSelectedTab] = useState('definition')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const scrollRef = useRef(null)

  // Load database
  useEffect(() => {
    setLoading(true)
    fetch('/data/attack-database.json')
      .then((r) => {
        if (!r.ok) throw new Error('Database not found. Run: node scripts/build-knowledge.mjs')
        return r.json()
      })
      .then((payload) => {
        setDatabase(payload)
        if (payload.attacks?.length > 0) {
          setSelectedId(payload.attacks[0].id)
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  // Auto-scroll to top when attack or tab changes
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTo({ top: 0, behavior: 'auto' })
    }
  }, [selectedId, selectedTab])

  // Fuzzy search
  const fuse = useMemo(() => {
    if (!database?.attacks?.length) return null
    return new Fuse(database.attacks, {
      includeScore: true,
      threshold: 0.35,
      ignoreLocation: true,
      minMatchCharLength: 2,
      keys: [
        { name: 'name', weight: 0.5 },
        { name: 'aliases', weight: 0.25 },
        { name: 'summary', weight: 0.1 },
        { name: 'searchText', weight: 0.15 },
      ],
    })
  }, [database])

  const results = useMemo(() => {
    if (!database?.attacks) return []
    const q = query.trim()
    if (!q) return database.attacks
    if (!fuse) return []
    return fuse.search(q, { limit: 300 }).map((i) => i.item)
  }, [database, query, fuse])

  const suggestions = useMemo(() => {
    if (!query.trim() || results.length > 0 || !fuse) return []
    return fuse.search(query.trim(), { limit: 5 }).map((i) => i.item.name)
  }, [query, results, fuse])

  const selectedAttack = useMemo(() => {
    if (!database?.attacks || !selectedId) return null
    return database.attacks.find((a) => a.id === selectedId) ?? null
  }, [database, selectedId])

  const tabCounts = useMemo(() => buildTabCounts(selectedAttack), [selectedAttack])

  // Auto-select first non-empty tab
  useEffect(() => {
    if (!selectedAttack) return
    const available = TABS.filter((t) => (tabCounts[t.key] ?? 0) > 0)
    if (available.length === 0) { setSelectedTab('definition'); return }
    if ((tabCounts[selectedTab] ?? 0) === 0) {
      setSelectedTab(available[0].key)
    }
  }, [selectedAttack, tabCounts, selectedTab])

  const openTopResult = useCallback(() => {
    if (results.length > 0) setSelectedId(results[0].id)
  }, [results])

  const renderTabBody = () => {
    if (!selectedAttack) {
      return <div className="empty-note"><p>← Select an attack from the index</p></div>
    }
    if (selectedTab === 'sources') return <SourceItems items={selectedAttack.documents} />
    if (selectedTab === 'knowledge') return <SectionItems items={selectedAttack.sections.other} />
    return <SectionItems items={selectedAttack.sections[selectedTab]} />
  }

  // Stats
  const totalDocs = database?.attacks?.reduce((s, a) => s + a.stats.documents, 0) ?? 0
  const totalLines = database?.attacks?.reduce((s, a) => s + a.stats.totalLines, 0) ?? 0

  return (
    <div className="page">
      {/* TOPBAR */}
      <header className="topbar">
        <div className="brandArea">
          <img src="/logo.svg" alt="CyberForge Logo" className="logoIcon" />
          <div className="brandTexts">
            <p className="brand">CyberForge Atlas</p>
            <h1>
              Attack <span className="accent">Intelligence</span> Matrix
            </h1>
          </div>
        </div>
        <div className="kpis">
          <div className="kpi">
            <span className="kpiLabel">Attacks</span>
            <span className="kpiValue">{database?.attacks?.length ?? '—'}</span>
          </div>
          <div className="kpi">
            <span className="kpiLabel">Files</span>
            <span className="kpiValue">{totalDocs || '—'}</span>
          </div>
          <div className="kpi">
            <span className="kpiLabel">Lines</span>
            <span className="kpiValue">{totalLines ? `${(totalLines / 1000).toFixed(1)}K` : '—'}</span>
          </div>
          <div className="kpi">
            <span className="kpiLabel">Status</span>
            <span className="kpiValue" style={{ color: '#39ff14' }}>ONLINE</span>
          </div>
        </div>
      </header>

      {/* SEARCH */}
      <section className="search">
        <div className="searchRow">
          <div className="searchInputWrap">
            <input
              id="q"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') openTopResult() }}
              placeholder="Search attacks, payloads, techniques, CVEs..."
              autoComplete="off"
              spellCheck="false"
            />
          </div>
          <button className="searchBtn" type="button" onClick={openTopResult}>
            Execute
          </button>
        </div>
        {suggestions.length > 0 && (
          <p className="suggestions">
            Did you mean:{' '}
            {suggestions.map((s) => (
              <button key={s} type="button" onClick={() => setQuery(s)}>{s}</button>
            ))}
          </p>
        )}
      </section>

      {error && <p className="error">[ ERROR ] {error}</p>}

      {/* MAIN LAYOUT */}
      <section className="layout">
        {/* SIDEBAR */}
        <aside className="sidebar">
          <div className="panelHead">
            <h2>Threat Index</h2>
            <span className="badge">{results.length}</span>
          </div>
          <div className="attackList">
            {loading && <div className="empty-note"><p>Loading database...</p></div>}
            {!loading && results.length === 0 && (
              <div className="empty-note"><p>No matches. Try a different query.</p></div>
            )}
            {results.map((attack) => (
              <AttackListItem 
                key={attack.id}
                attack={attack}
                isActive={selectedId === attack.id}
                onClick={() => setSelectedId(attack.id)}
              />
            ))}
          </div>
        </aside>

        {/* CONTENT */}
        <main className="content">
          <div className="contentHeader">
            <h2>
              {selectedAttack
                ? <><span className="attackName">{selectedAttack.name}</span></>
                : 'Select an Attack'}
            </h2>
            <span className="docCount">
              {selectedAttack ? `${selectedAttack.stats.documents} merged files` : '—'}
            </span>
          </div>

          <p className="summary">
            {selectedAttack?.summary ?? 'Choose an attack from the index to view its complete dossier.'}
          </p>

          <div className="tabs">
            {TABS.map((tab) => {
              const count = tabCounts[tab.key] ?? 0
              if (count === 0) return null
              return (
                <button
                  type="button"
                  key={tab.key}
                  className={`tab ${selectedTab === tab.key ? 'active' : ''}`}
                  onClick={() => setSelectedTab(tab.key)}
                >
                  {tab.icon} {tab.label}
                  <span className="count">{count}</span>
                </button>
              )
            })}
          </div>

          <div className="tabBody" ref={scrollRef}>{renderTabBody()}</div>
        </main>
      </section>
    </div>
  )
}

export default App
