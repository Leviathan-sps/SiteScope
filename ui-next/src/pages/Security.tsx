import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { type Report } from "@/lib/report"
import { Check, TriangleAlert, X } from "lucide-react"

// headers are graded server-side; this page only decides how to show the
// grade and which failures deserve to be shouted about.
export function Security({ r }: { r: Report }) {
  const h = r.headers
  const present = h.security.filter((s: any) => s.status === "ok").length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Security headers</h1>
        <p className="text-sm text-muted-foreground mt-1">
          The six headers that most affect how safely a browser treats the page.
        </p>
      </div>

      <Card>
        <CardContent className="p-6 flex items-center gap-6">
          <div className="text-5xl font-bold">{h.grade}</div>
          <div className="flex-1">
            <div className="text-sm mb-2">
              <strong>{h.score}</strong>
              <span className="text-muted-foreground">/100</span> · {present} of {h.security.length} headers in place
            </div>
            <Progress value={h.score} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Header by header</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableBody>
              {h.security.map((s: any, n: number) => (
                <TableRow key={n}>
                  <TableCell className="w-8">
                    {s.status === "ok" ? (
                      <Check className="size-4 text-emerald-500" />
                    ) : s.status === "weak" ? (
                      <TriangleAlert className="size-4 text-amber-500" />
                    ) : (
                      <X className="size-4 text-red-500" />
                    )}
                  </TableCell>
                  <TableCell className="font-medium">{s.label}</TableCell>
                  <TableCell className="text-muted-foreground text-sm">{s.note || s.status}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className={h.csp ? (h.csp.strict ? "" : "border-amber-500/50") : "border-red-500/50"}>
        <CardHeader>
          <CardTitle>
            Content-Security-Policy{" "}
            {h.csp && (
              <span className="text-muted-foreground font-normal text-sm">({h.csp.count} directives)</span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!h.csp ? (
            <p className="text-sm text-muted-foreground">
              No CSP header — the page has no script-source restrictions at all.
            </p>
          ) : h.csp.weaknesses.length ? (
            <div className="space-y-2">
              {h.csp.weaknesses.map((w: string, n: number) => (
                <Alert key={n}>
                  <TriangleAlert className="size-4" />
                  <AlertDescription>{w}</AlertDescription>
                </Alert>
              ))}
            </div>
          ) : (
            <p className="text-sm text-emerald-600 dark:text-emerald-400">
              No obvious weaknesses in the policy.
            </p>
          )}
          {h.csp && (
            <Accordion type="single" collapsible className="mt-4">
              <AccordionItem value="raw">
                <AccordionTrigger className="text-sm">Raw policy</AccordionTrigger>
                <AccordionContent>
                  <p className="font-mono text-xs break-all text-muted-foreground">{h.csp.raw}</p>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Server &amp; transfer</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {[
            ["Server", h.server.server],
            ["X-Powered-By", h.server.poweredBy],
            ["Compression", h.transfer.contentEncoding],
          ].map(([k, v]) => (
            <Badge key={k as string} variant="outline">
              {k}: {v || "—"}
            </Badge>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

// hsts preload eligibility (max-age >= 1y, includeSubDomains, preload) is
// checkable from the header alone. left out until the analyzer returns the
// parsed directives rather than the raw string.
// function preloadReady(hsts) { ... }
