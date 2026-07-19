import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead } from "@/components/Stat"
import { type Report } from "@/lib/report"
import { Check, TriangleAlert, X } from "lucide-react"

// a flag that's set is fine, a flag that's missing is the whole point of the
// page — so missing reads red rather than just absent.
function Flag({ on }: { on: boolean }) {
  return on ? <Check className="size-4 text-emerald-600" /> : <X className="size-4 text-red-600" />
}

export function Cookies({ r }: { r: Report }) {
  const ck = r.cookies

  return (
    <div className="space-y-6">
      <PageHead
        title="Cookies"
        lead="Every cookie the response set, and whether its flags keep it out of reach of scripts and plain http."
      />

      {ck.issues.length > 0 && (
        <div className="space-y-2">
          {ck.issues.map((issue: string, n: number) => (
            <Alert key={n}>
              <TriangleAlert className="size-4" />
              <AlertDescription>{issue}</AlertDescription>
            </Alert>
          ))}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>
            Set-Cookie <span className="text-muted-foreground font-normal text-sm">({ck.count})</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {ck.count === 0 ? (
            <p className="text-sm text-muted-foreground">
              No cookies set on this response. Nothing to leak.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Secure</TableHead>
                  <TableHead>HttpOnly</TableHead>
                  <TableHead>SameSite</TableHead>
                  <TableHead>Domain</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ck.cookies.map((c: any) => (
                  <TableRow key={c.name}>
                    <TableCell className="font-mono text-xs">{c.name}</TableCell>
                    <TableCell>
                      <Flag on={!!c.secure} />
                    </TableCell>
                    <TableCell>
                      <Flag on={!!c.httpOnly} />
                    </TableCell>
                    <TableCell className="text-xs">{c.sameSite || "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{c.domain || "—"}</TableCell>
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

// possible extra column: expiry, split into session vs persistent. the parser
// keeps max-age but not the computed date, so it'd need a bit of work first.
// const expiry = (c) => (c.maxAge ? new Date(Date.now() + c.maxAge * 1000) : "session")
