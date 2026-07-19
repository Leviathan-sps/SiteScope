import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead } from "@/components/Stat"
import { type Report } from "@/lib/report"

// confidence -> badge look. high is worth a solid badge, medium reads quieter
// so a page full of guesses doesn't look authoritative.
const confVariant = (c: string) => (c === "high" ? "default" : "secondary")

export function Technologies({ r }: { r: Report }) {
  const byCategory: Record<string, any[]> = {}
  for (const f of r.frameworks) {
    ;(byCategory[f.category] ||= []).push(f)
  }

  return (
    <div className="space-y-6">
      <PageHead
        title="Technologies"
        lead="What the page is built with, inferred from markup, headers and asset paths."
      />

      {r.frameworks.length === 0 ? (
        <Card>
          <CardContent className="p-6">
            <p className="text-sm text-muted-foreground">
              Nothing detected. Plenty of sites use a custom or server-rendered stack that leaves no fingerprint.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            {r.frameworks.map((f: any, n: number) => (
              <Badge key={n} variant={confVariant(f.confidence)}>
                {f.name}
                {f.version ? ` ${f.version}` : ""}
              </Badge>
            ))}
          </div>

          {Object.entries(byCategory).map(([cat, list]) => (
            <Card key={cat}>
              <CardHeader>
                <CardTitle className="capitalize">
                  {cat}{" "}
                  <span className="text-muted-foreground font-normal text-sm">({list.length})</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Evidence</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {list.map((f, n) => (
                      <TableRow key={n}>
                        <TableCell className="font-medium">{f.name}</TableCell>
                        <TableCell className="font-mono text-xs">{f.version || "—"}</TableCell>
                        <TableCell>
                          <Badge variant={confVariant(f.confidence)}>{f.confidence}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">
                          {(f.evidence || []).join(" · ")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          ))}
        </>
      )}
    </div>
  )
}

// idea: group by vendor rather than category, so all the google/cloudflare
// bits collapse into one row. needs a vendor map the detector doesn't have yet.
// function byVendor(frameworks) {
//   return groupBy(frameworks, (f) => VENDORS[f.name] || "other")
// }
