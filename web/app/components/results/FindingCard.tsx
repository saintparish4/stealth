'use client'

import { AlertTriangle, AlertCircle, Info, ChevronDown, ChevronUp, Lightbulb } from 'lucide-react'
import { useState } from 'react'
import { Card, CardContent, CardHeader } from '../../ui/card'
import { Badge } from '../../ui/badge'
import type { Finding } from '../../lib/scanner'

interface FindingCardProps {
  finding: Finding
  index: number
  onLineClick?: (line: number) => void
}

const severityConfig: Record<string, {
  icon: typeof AlertTriangle
  variant: 'critical' | 'high' | 'medium' | 'low'
  color: string
  bg: string
  border: string
}> = {
  CRITICAL: {
    icon: AlertTriangle,
    variant: 'critical' as const,
    color: 'text-red-500',
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
  },
  HIGH: {
    icon: AlertTriangle,
    variant: 'high' as const,
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
  },
  MEDIUM: {
    icon: AlertCircle,
    variant: 'medium' as const,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/20',
  },
  LOW: {
    icon: Info,
    variant: 'low' as const,
    color: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/20',
  },
}

export default function FindingCard({ finding, index, onLineClick }: FindingCardProps) {
  const [expanded, setExpanded] = useState(index < 3) // Auto-expand first 3
  const config = severityConfig[finding.severity]
  const Icon = config.icon

  return (
    <Card className={`${config.border.replace('/20', '/15')} transition-all duration-300 hover:border-opacity-60`}>
      <CardHeader className="pb-3">
        <div 
          className="flex items-start justify-between cursor-pointer"
          onClick={() => setExpanded(!expanded)}
        >
          <div className="flex items-start gap-4">
            <div className={`p-2.5 rounded-lg ${config.bg}`}>
              <Icon className={`w-5 h-5 ${config.color}`} />
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2.5 flex-wrap">
                <Badge variant={config.variant}>
                  {finding.severity}
                </Badge>
                <Badge variant="outline">
                  Confidence: {finding.confidence}
                </Badge>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onLineClick?.(finding.line)
                  }}
                  className="text-xs font-mono text-primary/80 hover:text-primary transition-colors font-light"
                >
                  Line {finding.line}
                </button>
              </div>
              <h3 className="font-light text-foreground tracking-tight">
                {finding.vulnerability_type}
              </h3>
            </div>
          </div>
          <button className="p-1.5 hover:bg-secondary/50 rounded transition-colors">
            {expanded ? (
              <ChevronUp className="w-5 h-5 text-muted-foreground/60" />
            ) : (
              <ChevronDown className="w-5 h-5 text-muted-foreground/60" />
            )}
          </button>
        </div>
      </CardHeader>
      
      {expanded && (
        <CardContent className="space-y-5 pt-0">
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground/80 font-light leading-relaxed">
              {finding.message}
            </p>
          </div>
          
          <div className={`p-5 rounded-lg ${config.bg} ${config.border.replace('/20', '/15')} border`}>
            <div className="flex items-start gap-3">
              <Lightbulb className={`w-4 h-4 mt-0.5 ${config.color}`} />
              <div>
                <span className="text-xs font-light uppercase tracking-wider text-muted-foreground/70">
                  Recommendation
                </span>
                <p className="text-sm text-foreground/90 mt-2 font-light leading-relaxed">
                  {finding.suggestion}
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  )
}