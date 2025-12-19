import Header from './components/scanner/Header'
import ScannerForm from './components/scanner/ScannerForm'

export default function HomePage() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background via-background to-background/95">
      <Header />
      
      <main className="container mx-auto px-6">
        {/* Hero Section - Minimalist */}
        <div className="text-center pt-24 pb-32 max-w-3xl mx-auto">
          <h1 className="text-5xl md:text-7xl font-light tracking-tight mb-8 leading-[1.1]">
            Smart Contract
            <br />
            <span className="text-primary/90 font-normal">Security Scanner</span>
          </h1>
          <p className="text-lg md:text-xl text-muted-foreground/80 font-light leading-relaxed max-w-xl mx-auto">
            Detect vulnerabilities in your Solidity contracts before deployment.
            <br />
            Powered by static analysis and battle-tested heuristics.
          </p>
        </div>

        {/* Scanner Form - The Focus */}
        <div className="max-w-6xl mx-auto pb-32">
          <ScannerForm />
        </div>

        {/* Minimal Footer */}
        <div className="text-center pb-16">
          <div className="inline-flex items-center gap-6 text-xs text-muted-foreground/60 font-light tracking-wide">
            <span>Built with Rust + Next.js</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
            <span>Open Source</span>
            <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
            <span>No data stored</span>
          </div>
        </div>
      </main>
    </div>
  )
}