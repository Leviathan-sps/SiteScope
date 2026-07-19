import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Stat } from "@/components/Stat"
import { fmtBytes, gradeTone, tone, type Report } from "@/lib/report"

// the landing page after a scan: tiles first, then whatever went wrong.
// anything needing more than a couple of cards gets its own page instead.
export function Overview({ r }: { r: Report }) {
  const chain = r.meta.redirectChain || []
  const score = r.score

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Overview</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {r.meta.finalUrl} — status {r.meta.status}, {fmtBytes(r.meta.bytes)}, {r.meta.elapsedMs}ms
          {r.meta.redirected ? ", redirected" : ""}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        {score?.score != null && (
          <Stat value={score.grade} label={`overall health (${score.score}/100)`} band={gradeTone(score.grade)} />
        )}
        <Stat value={r.frameworks.length} label="technologies" />
        <Stat value={r.headers.grade} label="security grade" band={gradeTone(r.headers.grade)} />
        <Stat value={r.cookies.count} label="cookies" />
        <Stat value={r.seo.score} label="SEO score" band={tone(r.seo.score)} />
        <Stat value={r.network.total} label="resources" />
      </div>

      {score?.topIssues?.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Top issues</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {score.topIssues.map((i: any, n: number) => (
              <Alert key={n}>
                <AlertDescription>
                  <Badge variant="outline" className="mr-2">
                    {i.source}
                  </Badge>
                  {i.label}
                </AlertDescription>
              </Alert>
            ))}
          </CardContent>
        </Card>
      )}

      {chain.length > 0 && (
        <Card className={r.meta.insecureHop ? "border-red-500/50" : ""}>
          <CardHeader>
            <CardTitle>
              Redirect chain{" "}
              <span className="text-muted-foreground font-normal text-sm">
                ({chain.length} hop{chain.length > 1 ? "s" : ""})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>To</TableHead>
                  <TableHead>Note</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {chain.map((hop: any, n: number) => (
                  <TableRow key={n}>
                    <TableCell>
                      <Badge variant={hop.downgrade ? "destructive" : "secondary"}>{hop.status}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs break-all">{hop.to}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {[hop.downgrade && "https → http", hop.crossHost && "cross-host"]
                        .filter(Boolean)
                        .join(", ") || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {r.meta.insecureHop && (
              <Alert variant="destructive" className="mt-4">
                <AlertDescription>
                  This chain drops from https to http — anything sent on that hop travels in the clear.
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// a sparkline of past scores for the same host would sit well next to the
// tiles, but nothing persists scans yet — it would have one data point.
// function ScoreTrend({ history }) { ... }
