import { FileQuestion, ArrowLeft } from 'lucide-react'
import Link from 'next/link'
import Header from '../../components/scanner/Header'
import { Button } from '../../ui/button'

export default function NotFound() {
  return (
    <div className="min-h-screen">
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