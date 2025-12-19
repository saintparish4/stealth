import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '../lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-md px-2.5 py-0.5 text-xs font-light font-mono tracking-wide transition-all duration-200',
  {
    variants: {
      variant: {
        default: 'border border-border/50 bg-secondary/50 text-secondary-foreground',
        critical: 'bg-red-500/10 text-red-400/90 border border-red-500/20',
        high: 'bg-red-500/8 text-red-400/80 border border-red-500/15',
        medium: 'bg-amber-500/8 text-amber-400/80 border border-amber-500/15',
        low: 'bg-blue-500/8 text-blue-400/80 border border-blue-500/15',
        success: 'bg-green-500/8 text-green-400/80 border border-green-500/15',
        outline: 'border border-border/50 text-foreground/80',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }