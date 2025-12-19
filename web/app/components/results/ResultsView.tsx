'use client'

import { useState, useCallback } from 'react'
import dynamic from 'next/dynamic'
import { ArrowLeft, Code, List, Download } from 'lucide-react'
import Link from 'next/link'
import { Button } from '../../ui/button'
import { Card, CardContent } from '../../ui/card'
import FindingCard from './FindingCard'
import Statistics from './Statistics'
import type { ScanResult } from '../../lib/scanner'

const CodeEditor = dynamic(
  () => import('../../components/scanner/CodeEditor'),
  { 
    ssr: false,
    loading: () => (
      <div className="rounded-lg overflow-hidden border border-border/50 bg-card/50">
        <div className="flex items-center justify-center h-[500px]">
          <div className="text-muted-foreground font-mono text-sm font-light">
            Loading editor...
          </div>
        </div>
      </div>
    )
  }
)

interface ResultsViewProps {
  result: ScanResult
}

type ViewMode = 'split' | 'findings' | 'code'

export default function ResultsView({ result }: ResultsViewProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('split')
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')

  const handleLineClick = useCallback((line: number) => {
    setHighlightedLine(line)
    // Scroll to code view if in split mode
    if (viewMode === 'split' || viewMode === 'code') {
      const editorElement = document.getElementById('code-viewer')
      editorElement?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, [viewMode])

  const filteredFindings = result.findings.filter(finding => {
    if (filterSeverity === 'all') return true
    return finding.severity.toLowerCase() === filterSeverity.toLowerCase()
  })

  const highlightLines = highlightedLine 
    ? [highlightedLine] 
    : result.findings.map(f => f.line)

  const downloadReport = () => {
    const report = {
      scan_id: result.id,
      timestamp: result.timestamp,
      filename: result.filename,
      statistics: result.statistics,
      findings: result.findings,
    }
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vanguard-report-${result.id}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="flex items-center justify-between">
        <Link href="/">
          <Button variant="ghost" className="gap-2 text-muted-foreground hover:text-foreground font-light">
            <ArrowLeft className="w-4 h-4" />
            New Scan
          </Button>
        </Link>
        
        <div className="flex items-center gap-3">
          {/* View Mode Toggle */}
          <div className="flex bg-secondary/50 rounded-lg p-1 border border-border/50">
            <button
              onClick={() => setViewMode('split')}
              className={`px-4 py-2 rounded-md text-sm font-light transition-all ${
                viewMode === 'split' 
                  ? 'bg-background text-foreground shadow-sm' 
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Split
            </button>
            <button
              onClick={() => setViewMode('findings')}
              className={`px-4 py-2 rounded-md text-sm font-light transition-all flex items-center gap-1.5 ${
                viewMode === 'findings' 
                  ? 'bg-background text-foreground shadow-sm' 
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <List className="w-4 h-4" />
              Findings
            </button>
            <button
              onClick={() => setViewMode('code')}
              className={`px-4 py-2 rounded-md text-sm font-light transition-all flex items-center gap-1.5 ${
                viewMode === 'code' 
                  ? 'bg-background text-foreground shadow-sm' 
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Code className="w-4 h-4" />
              Code
            </button>
          </div>
          
          <Button variant="ghost" onClick={downloadReport} className="font-light">
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Statistics */}
      <Statistics result={result} />

      {/* Filter */}
      {result.findings.length > 0 && (
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted-foreground/70 font-light">Filter:</span>
          <div className="flex bg-secondary/50 rounded-lg p-1 border border-border/50">
            {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
              <button
                key={severity}
                onClick={() => setFilterSeverity(severity)}
                className={`px-4 py-1.5 rounded text-xs font-light capitalize transition-all ${
                  filterSeverity === severity
                    ? 'bg-background text-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {severity}
              </button>
            ))}
          </div>
          <span className="text-sm text-muted-foreground/60 font-light">
            Showing {filteredFindings.length} of {result.findings.length}
          </span>
        </div>
      )}

      {/* Main Content */}
      <div className={`grid gap-6 ${
        viewMode === 'split' ? 'lg:grid-cols-2' : 'grid-cols-1'
      }`}>
        {/* Findings List */}
        {(viewMode === 'split' || viewMode === 'findings') && (
          <div className="space-y-6">
            <h2 className="text-xl font-light tracking-tight flex items-center gap-3">
              <List className="w-5 h-5 text-primary/80" />
              Findings
            </h2>
            {filteredFindings.length === 0 ? (
              <Card>
                <CardContent className="p-8 text-center">
                  <p className="text-muted-foreground">
                    {result.findings.length === 0 
                      ? 'No vulnerabilities detected!'
                      : 'No findings match the current filter.'}
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {filteredFindings.map((finding, index) => (
                  <FindingCard
                    key={`${finding.line}-${index}`}
                    finding={finding}
                    index={index}
                    onLineClick={handleLineClick}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Code Viewer */}
        {(viewMode === 'split' || viewMode === 'code') && (
          <div className="space-y-6" id="code-viewer">
            <h2 className="text-xl font-light tracking-tight flex items-center gap-3">
              <Code className="w-5 h-5 text-primary/80" />
              Source Code
            </h2>
            <CodeEditor
              value={result.source_code}
              onChange={() => {}}
              readOnly
              highlightLines={highlightLines}
              height={viewMode === 'code' ? '600px' : '500px'}
            />
            {highlightedLine && (
              <p className="text-sm text-muted-foreground/70 font-light">
                Highlighting line {highlightedLine}
                <button
                  onClick={() => setHighlightedLine(null)}
                  className="ml-3 text-primary/80 hover:text-primary transition-colors font-light"
                >
                  Clear
                </button>
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}