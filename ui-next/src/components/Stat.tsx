import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { Check, X } from "lucide-react"

// one number plus its label. the tile strip on several pages is just these
// repeated, so the sizing lives here rather than in every page.
export function Stat({
  value,
  label,
  band,
}: {
  value: React.ReactNode
  label: string
  band?: "ok" | "warn" | "bad"
}) {
  return (
    <Card className="flex-1 min-w-[8rem]">
      <CardContent className="px-4 py-3.5 text-center">
        <div
          className={cn(
            "text-[1.75rem] leading-none font-semibold tabular-nums",
            band === "ok" && "text-emerald-700 dark:text-emerald-400",
            band === "warn" && "text-amber-700 dark:text-amber-400",
            band === "bad" && "text-red-700 dark:text-red-400"
          )}
        >
          {value}
        </div>
        <div className="mt-1.5 text-xs text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  )
}

// a labelled row inside a card — replaces the <dl class="kv"> from the old ui.
// the label column is fixed so rows line up down the page even across cards.
export function Row({ label, children }: { label: string; children?: React.ReactNode }) {
  return (
    <div className="flex gap-4 py-2 border-b border-border/40 last:border-0 text-sm">
      <div className="w-40 shrink-0 text-muted-foreground">{label}</div>
      <div className="min-w-0 break-words">{children ?? "—"}</div>
    </div>
  )
}

// every page opens the same way, so the heading spacing only needs deciding once
export function PageHead({ title, lead }: { title: string; lead: string }) {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="text-sm text-muted-foreground mt-1 max-w-2xl">{lead}</p>
    </div>
  )
}

// the analyzers all return checks[] in the same {label, pass} shape, so seo,
// performance and crawlability can share one renderer. failures sort first —
// nobody scrolls past twelve green ticks to find the one red cross.
export function CheckList({ checks }: { checks: Array<{ label: string; pass: boolean }> }) {
  const sorted = [...checks].sort((a, b) => Number(a.pass) - Number(b.pass))
  return (
    <ul className="space-y-1.5">
      {sorted.map((c, n) => (
        <li key={n} className="flex gap-2 text-sm items-start">
          {c.pass ? (
            <Check className="size-4 text-emerald-600 mt-0.5 shrink-0" />
          ) : (
            <X className="size-4 text-red-600 mt-0.5 shrink-0" />
          )}
          <span className={c.pass ? "text-muted-foreground" : ""}>{c.label}</span>
        </li>
      ))}
    </ul>
  )
}

// a compact variant of Stat for sidebars was drafted here, but every page
// ended up wanting the full-width strip instead. left in case a denser
// layout comes back.
// export function MiniStat({ value, label }) {
//   return <div className="text-sm"><b>{value}</b> <span className="text-muted-foreground">{label}</span></div>
// }
