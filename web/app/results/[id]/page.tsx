'use client'

import { useEffect, useState } from 'react'
import { use } from 'react'
import Link from 'next/link'
import Header from '../../components/scanner/Header'
import ResultsView from '../../components/results/ResultsView'
import type { ScanResult } from '../../lib/scanner'
import { Loader2, FileQuestion, ArrowLeft } from 'lucide-react'
import { Button } from '../../ui/button'

interface ResultsPageProps {
  params: Promise<{
    id: string
  }>
}

export default function ResultsPage({ params }: ResultsPageProps) {
  const { id } = use(params)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  useEffect(() => {
    // Skip if we already have a result (prevents re-fetch on HMR/Fast Refresh)
    if (result) return
    
    async function loadResult() {
      const storageKey = `scan-result-${id}`
      
      // First try to get from sessionStorage (set by ScannerForm after scan)
      const cached = sessionStorage.getItem(storageKey)
      
      if (cached) {
        try {
          const parsed = JSON.parse(cached)
          setResult(parsed)
          setLoading(false)
          // Clean up after successfully setting result
          // Use setTimeout to ensure state is committed before cleanup
          setTimeout(() => sessionStorage.removeItem(storageKey), 100)
          return
        } catch {
          // Invalid JSON, continue to API fetch
        }
      }

      // Fallback to API fetch
      try {
        const response = await fetch(`/api/scan/${id}`)
        if (response.ok) {
          const data = await response.json()
          setResult(data)
        } else {
          setError(true)
        }
      } catch {
        setError(true)
      } finally {
        setLoading(false)
      }
    }

    loadResult()
  }, [id, result])

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-background via-background to-background/95">
        <Header />
        <main className="container mx-auto px-6 pt-24 pb-32">
          <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
            <Loader2 className="w-8 h-8 animate-spin text-primary/60" />
            <p className="text-muted-foreground font-light">Loading scan results...</p>
          </div>
        </main>
      </div>
    )
  }

  if (error || !result) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-background via-background to-background/95">
        <Header />
        <main className="container mx-auto px-6 py-8">
          <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-6">
            <div className="p-6 bg-secondary rounded-2xl border border-border">
              <FileQuestion className="w-16 h-16 text-muted-foreground" />
            </div>
            <div className="text-center space-y-2">
              <h1 className="text-2xl font-bold">Scan Not Found</h1>
              <p className="text-muted-foreground max-w-md">
                This scan result doesn&apos;t exist or has expired. 
                Scan results are stored temporarily and may be cleared.
              </p>
            </div>
            <Link href="/">
              <Button>
                <ArrowLeft className="w-4 h-4 mr-2" />
                Start New Scan
              </Button>
            </Link>
          </div>
        </main>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-background via-background to-background/95">
      <Header />
      
      <main className="container mx-auto px-6 pt-24 pb-32">
        <ResultsView result={result} />
      </main>
    </div>
  )
}