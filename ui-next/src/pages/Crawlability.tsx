import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { PageHead, Row, CheckList } from "@/components/Stat"
import { type Report } from "@/lib/report"

export function Crawlability({ r }: { r: Report }) {
  const c = r.crawl
  if (!c) return null

  return (
    <div className="space-y-6">
      <PageHead
        title="Crawlability"
        lead="What robots.txt and the sitemap tell a crawler it may read, and whether they agree with each other."
      />

      <Card>
        <CardContent className="p-6">
          <div className="flex items-baseline gap-2 mb-3">
            <span className="text-3xl font-semibold tabular-nums">{c.score}</span>
            <span className="text-muted-foreground text-sm">/100</span>
          </div>
          <Progress value={c.score} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>robots.txt</CardTitle>
        </CardHeader>
        <CardContent>
          <Row label="Present">
            <Badge variant={c.robotsTxt.present ? "outline" : "destructive"}>
              {c.robotsTxt.present ? "found" : "not found"}
            </Badge>
          </Row>
          {c.robotsTxt.crawlDelay != null && <Row label="Crawl-delay">{c.robotsTxt.crawlDelay}s</Row>}
          {c.robotsTxt.sitemaps?.length > 0 && (
            <Row label="Sitemap lines">
              <span className="font-mono text-xs break-all">{c.robotsTxt.sitemaps.join(", ")}</span>
            </Row>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sitemap</CardTitle>
        </CardHeader>
        <CardContent>
          <Row label="Present">
            <Badge variant={c.sitemap.present ? "outline" : "destructive"}>
              {c.sitemap.present ? "found" : "not found"}
            </Badge>
          </Row>
          {c.sitemap.present && (
            <Row label="Contents">
              {c.sitemap.isIndex ? `index of ${c.sitemap.urlCount} sitemaps` : `${c.sitemap.urlCount} URLs`}
            </Row>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Checks</CardTitle>
        </CardHeader>
        <CardContent>
          <CheckList checks={c.checks} />
        </CardContent>
      </Card>
    </div>
  )
}

// we parse the allow/disallow rules already — showing which of the probed
// paths robots.txt actually blocks would tie this page to the path scan.
// function BlockedPaths({ rules, paths }) { ... }
