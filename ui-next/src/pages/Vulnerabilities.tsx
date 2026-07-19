import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Stat } from "@/components/Stat"
import { sevIcon, sevVariant, type Report } from "@/lib/report"

// findings come pre-sorted worst-first from the analyzer, so the table just
// renders them in order.
export function Vulnerabilities({ r }: { r: Report }) {
  const v = r.vulns

  if (!v) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold">Vulnerabilities</h1>
        <Alert>
          <AlertDescription>
            The vulnerability check runs as part of the <strong>deep scan</strong>. Tick that box and scan again to
            see findings.
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  const c = v.counts || {}

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Vulnerabilities</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {v.total} finding{v.total === 1 ? "" : "s"} · overall risk {v.risk}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Stat value={c.critical || 0} label="critical" band={c.critical ? "bad" : undefined} />
        <Stat value={c.high || 0} label="high" band={c.high ? "bad" : undefined} />
        <Stat value={c.medium || 0} label="medium" band={c.medium ? "warn" : undefined} />
        <Stat value={c.low || 0} label="low" />
        <Stat value={c.info || 0} label="info" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {!v.total ? (
            <p className="text-sm text-muted-foreground">
              Nothing obvious — this is a passive check, not a full scan.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Fix</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {v.findings.map((f: any) => (
                  <TableRow key={f.id}>
                    <TableCell>
                      <Badge variant={sevVariant(f.severity)}>
                        {sevIcon(f.severity)} {f.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium">{f.title}</div>
                      <div className="text-xs text-muted-foreground mt-1">{f.detail}</div>
                      {f.cve && (
                        <Badge variant="outline" className="mt-1 text-[10px]">
                          {f.cve}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{f.recommendation}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

// grouping findings by component instead of severity reads better on hosts
// with a dozen issues on the same library. severity-first wins for now.
// const byComponent = (findings) => groupBy(findings, (f) => f.component)
