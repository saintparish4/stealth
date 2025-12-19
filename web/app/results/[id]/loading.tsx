'use client'

import { Loader2, Shield } from 'lucide-react'
import Header from '../../components/scanner/Header'

export default function Loading() {
  return (
    <div className="min-h-screen">
      <Header />
      
      <main className="container mx-auto px-6 py-8">
        <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-6">
          <div className="relative">
            <div className="absolute inset-0 bg-primary/20 blur-3xl rounded-full animate-pulse" />
            <div className="relative p-6 bg-primary/10 rounded-2xl border border-primary/20">
              <Shield className="w-16 h-16 text-primary animate-pulse" />
            </div>
          </div>
          
          <div className="text-center space-y-2">
            <div className="flex items-center justify-center gap-2">
              <Loader2 className="w-5 h-5 animate-spin text-primary" />
              <span className="text-lg font-medium">Analyzing Contract...</span>
            </div>
            <p className="text-sm text-muted-foreground font-mono">
              Running 13 security detectors
            </p>
          </div>
          
          {/* Animated scan lines */}
          <div className="w-64 h-1 bg-secondary rounded-full overflow-hidden">
            <div className="h-full bg-primary rounded-full animate-[scan_1.5s_ease-in-out_infinite]" 
                 style={{ width: '30%' }} />
          </div>
        </div>
      </main>
      
      <style jsx>{`
        @keyframes scan {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(400%); }
        }
      `}</style>
    </div>
  )
}