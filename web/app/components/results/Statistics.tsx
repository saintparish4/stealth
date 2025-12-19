import { AlertTriangle, AlertCircle, Info, ShieldCheck, Clock, FileCode } from 'lucide-react'
import { Card, CardContent } from '../../ui/card'
import type { ScanResult } from '../../lib/scanner'

interface StatisticsProps {
  result: ScanResult
}

export default function Statistics({ result }: StatisticsProps) {
  const { statistics, scan_time_ms, filename } = result
  const total = statistics.critical + statistics.high + statistics.medium + statistics.low

  const stats = [
    {
      label: 'Critical',
      value: statistics.critical,
      icon: AlertTriangle,
      color: 'text-red-500',
      bg: 'bg-red-500/10',
      ring: 'ring-red-500/20',
    },
    {
      label: 'High',
      value: statistics.high,
      icon: AlertTriangle,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      ring: 'ring-red-500/20',
    },
    {
      label: 'Medium',
      value: statistics.medium,
      icon: AlertCircle,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10',
      ring: 'ring-amber-500/20',
    },
    {
      label: 'Low',
      value: statistics.low,
      icon: Info,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
      ring: 'ring-blue-500/20',
    },
  ]

  return (
    <div className="space-y-8">
      {/* Overall Status */}
      <Card className={total === 0 ? 'border-green-500/20' : 'border-red-500/20'}>
        <CardContent className="p-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-5">
              <div className={`p-3 rounded-xl transition-all ${total === 0 ? 'bg-green-500/8' : 'bg-red-500/8'}`}>
                {total === 0 ? (
                  <ShieldCheck className="w-7 h-7 text-green-500/80" />
                ) : (
                  <AlertTriangle className="w-7 h-7 text-red-500/80" />
                )}
              </div>
              <div>
                <h2 className="text-2xl font-light tracking-tight mb-1">
                  {total === 0 ? (
                    <span className="text-green-500/90">No Issues Found</span>
                  ) : (
                    <span className="text-red-400/90">{total} Issues Found</span>
                  )}
                </h2>
                <p className="text-muted-foreground/70 text-sm font-light">
                  {total === 0 
                    ? 'Your contract passed all security checks'
                    : `Found ${statistics.critical + statistics.high} critical/high severity issues`
                  }
                </p>
              </div>
            </div>
            <div className="text-right">
              <div className="flex items-center gap-2 text-muted-foreground/70 text-sm font-light mb-2">
                <FileCode className="w-4 h-4" />
                <span className="font-mono">{filename}</span>
              </div>
              <div className="flex items-center gap-2 text-muted-foreground/70 text-sm font-light">
                <Clock className="w-4 h-4" />
                <span>{scan_time_ms}ms</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {stats.map((stat) => {
          const Icon = stat.icon
          const borderColor = stat.ring.replace('ring-', 'border-').replace('/20', '/15')
          return (
            <Card key={stat.label} className={`border ${borderColor}`}>
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className={`p-2 rounded-lg ${stat.bg}`}>
                    <Icon className={`w-4 h-4 ${stat.color}`} />
                  </div>
                  <span className={`text-3xl font-light font-mono tracking-tight ${stat.value > 0 ? stat.color : 'text-muted-foreground/50'}`}>
                    {stat.value}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground/70 font-light">{stat.label}</p>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Confidence Distribution */}
      {total > 0 && (
        <Card>
          <CardContent className="p-5">
            <h3 className="text-sm font-light text-muted-foreground/70 mb-4 tracking-wide">
              Confidence Distribution
            </h3>
            <div className="flex gap-6">
              <div className="flex items-center gap-2.5">
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                <span className="text-sm font-light">High: {statistics.confidence_high}</span>
              </div>
              <div className="flex items-center gap-2.5">
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                <span className="text-sm font-light">Medium: {statistics.confidence_medium}</span>
              </div>
              <div className="flex items-center gap-2.5">
                <div className="w-2.5 h-2.5 rounded-full bg-blue-500/60" />
                <span className="text-sm font-light">Low: {statistics.confidence_low}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}