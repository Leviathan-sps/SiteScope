import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { PageHead, Row, Stat, CheckList } from "@/components/Stat"
import { fmtBytes, tone, type Report } from "@/lib/report"

export function Performance({ r }: { r: Report }) {
  const p = r.performance
  if (!p) return null

  return (
    <div className="space-y-6">
      <PageHead
        title="Performance budget"
        lead="A static budget check — request counts and weight, not a live lighthouse run."
      />

      <Card>
        <CardContent className="p-6">
          <div className="flex items-baseline gap-2 mb-3">
            <span className="text-3xl font-semibold tabular-nums">{p.score}</span>
            <span className="text-muted-foreground text-sm">/100</span>
          </div>
          <Progress value={p.score} />
        </CardContent>
      </Card>

      <div className="flex flex-wrap gap-3">
        <Stat value={p.requests} label="requests" band={tone(100 - Math.min(p.requests, 100))} />
        <Stat value={p.jsCount} label="scripts" />
        <Stat value={p.cssCount} label="stylesheets" />
        <Stat value={p.thirdPartyHosts} label="third-party hosts" />
      </div>

      {p.bytes && (
        <Card>
          <CardHeader>
            <CardTitle>Weight</CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="Total">{fmtBytes(p.bytes.total)}</Row>
            {p.bytes.html != null && <Row label="HTML">{fmtBytes(p.bytes.html)}</Row>}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Budget checks</CardTitle>
        </CardHeader>
        <CardContent>
          <CheckList checks={p.checks} />
        </CardContent>
      </Card>
    </div>
  )
}

// with --probe on we get real content-length per resource, so a "heaviest
// assets" table would be genuinely useful. only meaningful on probed runs
// though, so it needs an empty state first.
// function HeaviestAssets({ probed }) { ... }
