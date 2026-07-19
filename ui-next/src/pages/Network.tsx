import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead, Row, Stat } from "@/components/Stat"
import { fmtBytes, type Report } from "@/lib/report"
import { TriangleAlert } from "lucide-react"

export function Network({ r }: { r: Report }) {
  const n = r.network
  const mixed = n.mixedContent
  // biggest offenders first — a host pulling 40 files matters more than the
  // long tail of one-offs below it.
  const hosts = Object.entries(n.byHost).sort((a, b) => (b[1] as number) - (a[1] as number))

  return (
    <div className="space-y-6">
      <PageHead
        title="Network"
        lead="Every sub-resource the page references, split by where it comes from and what kind it is."
      />

      <div className="flex flex-wrap gap-3">
        <Stat value={n.total} label="resources" />
        <Stat value={n.firstParty} label="first-party" />
        <Stat value={n.thirdParty} label="third-party" band={n.thirdParty > 20 ? "warn" : undefined} />
        <Stat value={n.thirdPartyHosts.length} label="external hosts" />
      </div>

      {mixed?.applicable && mixed.total > 0 && (
        <Alert variant={mixed.active.length ? "destructive" : "default"}>
          <TriangleAlert className="size-4" />
          <AlertDescription>
            {mixed.active.length} active and {mixed.passive.length} passive resource(s) load over plain http.
            {mixed.active.length > 0 && " Browsers block the active ones outright."}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>By type</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {Object.entries(n.byType).map(([t, count]) => (
            <Badge key={t} variant="outline">
              {t}: {count as number}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>By host</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead className="text-right">Requests</TableHead>
                <TableHead>Party</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {hosts.map(([host, count]) => (
                <TableRow key={host}>
                  <TableCell className="font-mono text-xs">{host || "(inline)"}</TableCell>
                  <TableCell className="text-right tabular-nums">{count as number}</TableCell>
                  <TableCell>
                    {n.thirdPartyHosts.includes(host) ? (
                      <Badge variant="secondary">third-party</Badge>
                    ) : (
                      <Badge variant="outline">first-party</Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {n.probed && (
        <Card>
          <CardHeader>
            <CardTitle>Probed sample</CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="Sampled">{n.probed.sampled} resources</Row>
            <Row label="Weight">{fmtBytes(n.probed.totalBytes)}</Row>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// a waterfall chart would be the obvious next step here, but a single html
// fetch has no timing data — we'd only be able to fake the bars.
// function Waterfall({ items }) { ... }
