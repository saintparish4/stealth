import { Shield, Github, Terminal } from 'lucide-react'
import Link from 'next/link'

export default function Header() {
  return (
    <header className="border-b border-border/50 bg-background/80 backdrop-blur-md sticky top-0 z-50">
      <div className="container mx-auto px-6 py-5">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/10 blur-xl rounded-full group-hover:bg-primary/15 transition-all duration-300" />
              <div className="relative p-2 bg-primary/5 rounded-lg border border-primary/10 group-hover:border-primary/20 transition-all duration-300">
                <Shield className="w-5 h-5 text-primary/80" />
              </div>
            </div>
            <div>
              <h1 className="text-lg font-light tracking-wide">
                <span className="text-primary/90">VANGUARD</span>
              </h1>
              <p className="text-xs text-muted-foreground/70 font-mono font-light">
                Smart Contract Security
              </p>
            </div>
          </Link>

          {/* Navigation */}
          <nav className="flex items-center gap-8">
            <Link 
              href="/"
              className="text-sm text-muted-foreground/70 hover:text-foreground transition-colors duration-300 flex items-center gap-2 font-light"
            >
              <Terminal className="w-4 h-4" />
              Scanner
            </Link>
            <a
              href="https://github.com/saintparish4/stealth"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-muted-foreground/70 hover:text-foreground transition-colors duration-300 flex items-center gap-2 font-light"
            >
              <Github className="w-4 h-4" />
              GitHub
            </a>
          </nav>
        </div>
      </div>
    </header>
  )
}