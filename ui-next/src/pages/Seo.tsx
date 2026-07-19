import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { PageHead, Row, CheckList } from "@/components/Stat"
import { type Report } from "@/lib/report"

export function Seo({ r }: { r: Report }) {
  const s = r.seo

  return (
    <div className="space-y-6">
      <PageHead title="SEO" lead="On-page metadata, heading structure and the links search engines will follow." />

      <Card>
        <CardContent className="p-6">
          <div className="flex items-baseline gap-2 mb-3">
            <span className="text-3xl font-semibold tabular-nums">{s.score}</span>
            <span className="text-muted-foreground text-sm">/100</span>
          </div>
          <Progress value={s.score} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Metadata</CardTitle>
        </CardHeader>
        <CardContent>
          <Row label="Title">{s.title}</Row>
          <Row label="Description">{s.metaDescription}</Row>
          <Row label="Canonical">
            <span className="font-mono text-xs break-all">{s.canonical}</span>
          </Row>
          <Row label="Open Graph">
            {s.openGraph.length ? `${s.openGraph.length} tags` : "none"}
          </Row>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Structure</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2 mb-4">
            <Badge variant="outline">h1: {s.headings.h1}</Badge>
            <Badge variant="outline">h2: {s.headings.h2}</Badge>
            <Badge variant="outline">h3: {s.headings.h3}</Badge>
          </div>
          <Row label="Images">
            {s.images.total} total, {s.images.missingAlt} missing alt
          </Row>
          <Row label="Links">
            {s.links.internal} internal · {s.links.external} external
          </Row>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Checks</CardTitle>
        </CardHeader>
        <CardContent>
          <CheckList checks={s.checks} />
        </CardContent>
      </Card>
    </div>
  )
}

// a serp preview (title + url + description rendered the way google shows it)
// would make the length limits obvious at a glance. skipped for now — the
// truncation rules change often enough that a stale preview would mislead.
// function SerpPreview({ title, url, description }) { ... }
