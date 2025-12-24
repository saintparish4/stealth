'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import { Upload, Play, Loader2, AlertTriangle, Zap } from 'lucide-react'
import { Button } from '../../ui/button'
import { Card, CardContent } from '../../ui/card'

const CodeEditor = dynamic(
  () => import('./CodeEditor'),
  { 
    ssr: false,
    loading: () => (
      <div className="rounded-lg overflow-hidden border border-border/50 bg-card/50">
        <div className="flex items-center justify-center h-[630px]">
          <div className="text-muted-foreground font-mono text-sm font-light">
            Loading editor...
          </div>
        </div>
      </div>
    )
  }
)

const EXAMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: Reentrancy
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // External call before state change!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State change after external call
        balances[msg.sender] = 0;
    }
    
    // VULNERABLE: tx.origin
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
    
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
}`

export default function ScannerForm() {
  const router = useRouter()
  const [code, setCode] = useState(EXAMPLE_CONTRACT)
  const [filename, setFilename] = useState('contract.sol')
  const [isScanning, setIsScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please enter some code to scan')
      return
    }

    setIsScanning(true)
    setError(null)

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code,
          filename,
        }),
      })

      if (!response.ok) {
        throw new Error('Scan failed')
      }

      const result = await response.json()
      
      // Store result in sessionStorage for the results page to read
      // This works around Next.js module isolation issues with in-memory storage
      sessionStorage.setItem(`scan-result-${result.id}`, JSON.stringify(result))
      
      router.push(`/results/${result.id}`)
    } catch {
      setError('Failed to scan contract. Please try again.')
      setIsScanning(false)
    }
  }

  const loadExample = () => {
    setCode(EXAMPLE_CONTRACT)
    setFilename('VulnerableVault.sol')
    setError(null)
  }

  return (
    <div className="space-y-8">
      {/* Upload Area - Disabled for security */}
      <Card className="border-dashed border-2 border-foreground/30 cursor-not-allowed">
        <CardContent className="p-6">
          <div className="flex flex-col items-center justify-center text-center">
            <div className="p-3 rounded-full mb-4 bg-secondary/20">
              <Upload className="w-6 h-6 text-muted-foreground/60" />
            </div>
            <p className="text-base font-light mb-1 tracking-tight text-foreground/80">
              Drag & drop your Solidity file
            </p>
            <p className="text-xs text-muted-foreground/70 mb-4 font-light">
              or click to browse
            </p>
            <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-amber-500/10 border border-amber-500/20">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              <span className="text-xs text-amber-600 font-medium">
                Disabled — file upload not implemented for security reasons
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Code Editor */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground/70 font-light">File:</span>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="px-3 py-1.5 rounded-md border border-border/50 bg-background/50 text-sm font-light focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/30 transition-all w-64"
              placeholder="contract.sol"
            />
          </div>
          <Button variant="ghost" size="sm" onClick={loadExample} className="font-light">
            <Zap className="w-4 h-4 mr-2" />
            Load Example
          </Button>
        </div>
        
        <CodeEditor
          value={code}
          onChange={setCode}
          height="630px"
        />
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-3 p-4 rounded-lg bg-destructive/5 border border-destructive/20 text-destructive/90">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span className="text-sm font-light">{error}</span>
        </div>
      )}

      {/* Scan Button */}
      <div className="flex justify-end pt-4">
        <Button
          onClick={handleScan}
          disabled={isScanning || !code.trim()}
          size="lg"
          className="min-w-[200px] font-light"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-5 h-5 mr-2 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Play className="w-5 h-5 mr-2" />
              Scan Contract
            </>
          )}
        </Button>
      </div>
    </div>
  )
}