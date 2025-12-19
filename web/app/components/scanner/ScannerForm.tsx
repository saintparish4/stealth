'use client'

import { useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import dynamic from 'next/dynamic'
import { Upload, Play, FileCode, Loader2, AlertTriangle, Zap } from 'lucide-react'
import { Button } from '../../ui/button'
import { Card, CardContent } from '../../ui/card'

const CodeEditor = dynamic(
  () => import('./CodeEditor'),
  { 
    ssr: false,
    loading: () => (
      <div className="rounded-lg overflow-hidden border border-border/50 bg-card/50">
        <div className="flex items-center justify-center h-[450px]">
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
  const [dragActive, setDragActive] = useState(false)

  const handleFileUpload = useCallback((file: File) => {
    if (!file.name.endsWith('.sol')) {
      setError('Please upload a Solidity file (.sol)')
      return
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      const content = e.target?.result as string
      setCode(content)
      setFilename(file.name)
      setError(null)
    }
    reader.onerror = () => {
      setError('Failed to read file')
    }
    reader.readAsText(file)
  }, [])

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0])
    }
  }, [handleFileUpload])

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0])
    }
  }, [handleFileUpload])

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
      {/* Upload Area */}
      <Card
        className={`transition-all duration-300 ${
          dragActive 
            ? 'border-primary/30 bg-primary/5' 
            : 'border-dashed border-2 border-border/50'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <CardContent className="p-12">
          <div className="flex flex-col items-center justify-center text-center">
            <div className={`p-4 rounded-full mb-6 transition-all duration-300 ${
              dragActive ? 'bg-primary/10' : 'bg-secondary/30'
            }`}>
              <Upload className={`w-8 h-8 transition-colors ${dragActive ? 'text-primary/80' : 'text-muted-foreground/60'}`} />
            </div>
            <p className="text-lg font-light mb-2 tracking-tight">
              {dragActive ? 'Drop your file here' : 'Drag & drop your Solidity file'}
            </p>
            <p className="text-sm text-muted-foreground/70 mb-6 font-light">
              or click to browse
            </p>
            <input
              type="file"
              accept=".sol"
              onChange={handleFileInput}
              className="hidden"
              id="file-upload"
            />
            <label htmlFor="file-upload">
              <Button variant="ghost" className="cursor-pointer font-light">
                <FileCode className="w-4 h-4 mr-2" />
                Browse Files
              </Button>
            </label>
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
          height="450px"
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