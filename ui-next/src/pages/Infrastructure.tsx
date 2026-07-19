import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Row } from "@/components/Stat"
import { type Report } from "@/lib/report"

const kindVariant = (kind: string): "destructive" | "secondary" | "outline" =>
  kind === "sensitive" ? "destructive" : kind === "surface" ? "secondary" : "outline"

// hosting, certificate and dns posture, plus the active recon results when
// a deep scan was run. the recon cards stay hidden otherwise.
export function Infrastructure({ r }: { r: Report }) {
  const inf = r.infra
  const geo = inf.geo
  const rec = r.recon || {}
  const t = r.tls
  const dn = r.dns

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Infrastructure</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Where the site is hosted and how it resolves, plus certificate and DNS posture.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Where it lives</CardTitle>
        </CardHeader>
        <CardContent>
          <Row label="IP address">
            <span className="font-mono">{inf.primaryIp}</span>
          </Row>
          <Row label="Reverse DNS">{inf.reverse}</Row>
          {geo && (
            <>
              <Row label="Hosted by">
                {geo.org || geo.isp} {geo.asn && <span className="text-muted-foreground">({geo.asn})</span>}
              </Row>
              <Row label="Location">
                {geo.flag} {[geo.city, geo.region, geo.country].filter(Boolean).join(", ")}
              </Row>
            </>
          )}
          <Row label="Nameservers">
            <span className="font-mono text-xs">{(inf.ns || []).join(", ") || "—"}</span>
          </Row>
          <Row label="Mail (MX)">
            <span className="font-mono text-xs">{(inf.mx || []).join(", ") || "—"}</span>
          </Row>
        </CardContent>
      </Card>

      {t?.reachable && (
        <Card className={t.expired || !t.authorized ? "border-red-500/50" : t.expiringSoon ? "border-amber-500/50" : ""}>
          <CardHeader>
            <CardTitle>
              TLS certificate <span className="text-muted-foreground font-normal text-sm">({t.score}/100)</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="Issued to">{t.subject}</Row>
            <Row label="Issued by">{t.issuer}</Row>
            <Row label="Expires">
              {t.validTo?.slice(0, 10)}{" "}
              <span className="text-muted-foreground">({t.daysLeft} days)</span>
            </Row>
            <Row label="Protocol">
              <span className="font-mono">{t.protocol}</span>
            </Row>
            <Row label="Cipher">
              <span className="font-mono text-xs">{t.cipher}</span>
            </Row>
            <Row label="Covers">
              <span className="font-mono text-xs">{(t.names || []).join(", ")}</span>
            </Row>
            {t.checks
              .filter((c: any) => !c.pass)
              .map((c: any, n: number) => (
                <Alert variant="destructive" key={n} className="mt-2">
                  <AlertDescription>{c.label}</AlertDescription>
                </Alert>
              ))}
          </CardContent>
        </Card>
      )}

      {dn?.available && (
        <Card>
          <CardHeader>
            <CardTitle>
              Domain security <span className="text-muted-foreground font-normal text-sm">({dn.score}/100)</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="SPF">
              <span className="font-mono text-xs">{dn.spf?.record || "not published"}</span>
            </Row>
            <Row label="DMARC">{dn.dmarc ? `p=${dn.dmarc.policy}` : "not published"}</Row>
            <Row label="DKIM">{dn.dkim.present ? dn.dkim.found.join(", ") : "no common selector found"}</Row>
            <Row label="CAA">
              <span className="font-mono text-xs">{dn.caa.join(", ") || "none"}</span>
            </Row>
            {dn.checks
              .filter((c: any) => !c.pass)
              .map((c: any, n: number) => (
                <Alert key={n} className="mt-2">
                  <AlertDescription>{c.label}</AlertDescription>
                </Alert>
              ))}
          </CardContent>
        </Card>
      )}

      {!rec.ports && !rec.paths && !rec.subs && (
        <Alert>
          <AlertDescription>
            Tick <strong>deep scan</strong> before scanning to check open ports, probe common paths and look for
            subdomains. Active scanning sends real traffic — only run it against sites you own or are authorized to
            test.
          </AlertDescription>
        </Alert>
      )}

      {rec.ports && (
        <Card className={rec.ports.exposedSensitive.length ? "border-red-500/50" : ""}>
          <CardHeader>
            <CardTitle>
              Open ports{" "}
              <span className="text-muted-foreground font-normal text-sm">
                ({rec.ports.open.length} of {rec.ports.scanned})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Port</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Note</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rec.ports.open.map((p: any) => (
                  <TableRow key={p.port}>
                    <TableCell className="font-mono">{p.port}</TableCell>
                    <TableCell>
                      <Badge variant={p.sensitive ? "destructive" : "outline"}>{p.name}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">{p.note}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {rec.subs && (
        <Card className={rec.subs.exposedSensitive.length ? "border-red-500/50" : ""}>
          <CardHeader>
            <CardTitle>
              Subdomains{" "}
              <span className="text-muted-foreground font-normal text-sm">
                ({rec.subs.found.length} found of {rec.subs.checked})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {rec.subs.wildcard ? (
              <p className="text-sm text-muted-foreground">
                This domain uses wildcard DNS — every name resolves, so guessing can't tell real subdomains apart.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Subdomain</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Kind</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rec.subs.found.map((s: any) => (
                    <TableRow key={s.fqdn}>
                      <TableCell className="font-mono text-xs">
                        {s.fqdn}
                        {s.source === "cert" && (
                          <Badge variant="outline" className="ml-2 text-[10px]">
                            cert
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{s.addresses[0]}</TableCell>
                      <TableCell>
                        <Badge variant={kindVariant(s.kind)}>{s.kind}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {rec.paths && (
        <Card className={rec.paths.exposedSensitive.length ? "border-red-500/50" : ""}>
          <CardHeader>
            <CardTitle>
              Path discovery{" "}
              <span className="text-muted-foreground font-normal text-sm">
                ({rec.paths.found.length} found of {rec.paths.checked})
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead>Kind</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rec.paths.present.map((p: any) => (
                  <TableRow key={p.path}>
                    <TableCell>
                      <Badge variant={p.kind === "sensitive" && p.status < 400 ? "destructive" : "secondary"}>
                        {p.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{p.path}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">{p.kind}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// a small map pin from the geo lat/long would make the hosting location
// concrete, but every tile provider needs either a key or an external
// request, and this ui makes none.
// function GeoPin({ lat, lon }) { ... }
