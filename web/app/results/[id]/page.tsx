import { notFound } from 'next/navigation'
import Header from '../../components/scanner/Header'
import ResultsView from '../../components/results/ResultsView'
import { getScanResult } from '../../lib/scanner'

interface ResultsPageProps {
  params: Promise<{
    id: string
  }>
}

// Force dynamic rendering since we're fetching data
export const dynamic = 'force-dynamic'

async function getResult(id: string) {
  // In production, this would fetch from the API
  // For SSR, we can directly call the function
  const result = await getScanResult(id)
  return result
}

export default async function ResultsPage({ params }: ResultsPageProps) {
  const { id } = await params
  const result = await getResult(id)
  
  if (!result) {
    notFound()
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