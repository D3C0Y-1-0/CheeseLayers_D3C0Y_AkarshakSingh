import { AlertOctagon, AlertTriangle, ChevronDown, ChevronUp, Info, Minus } from 'lucide-react'
import type { Alert, Priority } from './api'

// Status colours always come with an icon and a word, so colour never carries the meaning alone.
const PRIORITY: Record<Priority, { label: string; icon: typeof Info }> = {
  critical: { label: 'Critical', icon: AlertOctagon },
  high: { label: 'High', icon: AlertTriangle },
  medium: { label: 'Medium', icon: ChevronUp },
  low: { label: 'Low', icon: ChevronDown },
}

export function PriorityBadge({ priority }: { priority: Priority }) {
  const { label, icon: Icon } = PRIORITY[priority]
  return <span className={`badge badge-${priority}`}><Icon aria-hidden className="size-3.5" />{label}</span>
}

export function SeverityBadge({ severity }: { severity: string | null }) {
  if (severity && severity in PRIORITY) return <PriorityBadge priority={severity as Priority} />
  return <Unknown />
}

export const Unknown = () => <span className="inline-flex items-center gap-1 text-grey-400"><Minus aria-hidden className="size-3" />Unknown</span>

export function Provenance({ alert }: { alert: Alert }) {
  const realCve = alert.threat_ids.some((t) => t.startsWith('CVE-'))
  return <span className="tag">{realCve ? 'Real CVE, simulated asset' : 'Simulated'}</span>
}

export function PageHead({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <header className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <h1 className="font-display text-[1.875rem] leading-none font-light text-white">{title}</h1>
      {children}
    </header>
  )
}

export function Panel({ title, children, className = '' }: { title?: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {title && <h2 className="panel-title">{title}</h2>}
      {children}
    </section>
  )
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-4 py-8 text-center text-grey-300">{children}</p>
}
