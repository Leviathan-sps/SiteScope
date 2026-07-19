import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Skeleton } from "@/components/ui/skeleton"
import { Overview } from "@/pages/Overview"
import { Security } from "@/pages/Security"
import { Infrastructure } from "@/pages/Infrastructure"
import { Vulnerabilities } from "@/pages/Vulnerabilities"
import { Technologies } from "@/pages/Technologies"
import { Cookies } from "@/pages/Cookies"
import { Seo } from "@/pages/Seo"
import { Network } from "@/pages/Network"
import { Performance } from "@/pages/Performance"
import { Crawlability } from "@/pages/Crawlability"
import { scan, type Report } from "@/lib/report"
import { Moon, Search, Sun, Telescope } from "lucide-react"

// one entry per page. keeping the list in one place means the tab strip and
// the panels below it can't drift out of sync as pages get added.
const PAGES = [
  { id: "overview", label: "Overview", render: (r: Report) => <Overview r={r} /> },
  { id: "technologies", label: "Technologies", render: (r: Report) => <Technologies r={r} /> },
  { id: "security", label: "Security", render: (r: Report) => <Security r={r} /> },
  { id: "vulnerabilities", label: "Vulnerabilities", render: (r: Report) => <Vulnerabilities r={r} /> },
  { id: "infrastructure", label: "Infrastructure", render: (r: Report) => <Infrastructure r={r} /> },
  { id: "cookies", label: "Cookies", render: (r: Report) => <Cookies r={r} /> },
  { id: "seo", label: "SEO", render: (r: Report) => <Seo r={r} /> },
  { id: "network", label: "Network", render: (r: Report) => <Network r={r} /> },
  { id: "performance", label: "Performance", render: (r: Report) => <Performance r={r} /> },
  { id: "crawlability", label: "Crawlability", render: (r: Report) => <Crawlability r={r} /> },
]

export default function App() {
  const [url, setUrl] = useState("")
  const [deep, setDeep] = useState(false)
  const [report, setReport] = useState<Report | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dark, setDark] = useState(() => localStorage.getItem("ss-theme") === "dark")

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark)
    localStorage.setItem("ss-theme", dark ? "dark" : "light")
  }, [dark])

  async function run(target: string) {
    if (!target || loading) return
    setLoading(true)
    setError(null)
    setReport(null)
    try {
      setReport(await scan(target, deep))
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b sticky top-0 bg-background/80 backdrop-blur z-10">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-3">
          <Telescope className="size-5 shrink-0" />
          <span className="font-semibold shrink-0">SiteScope</span>
          <form
            className="flex-1 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              run(url.trim())
            }}
          >
            <Input
              placeholder="example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1"
            />
            <Button type="submit" disabled={loading}>
              <Search className="size-4" />
              Scan
            </Button>
          </form>
          <label className="flex items-center gap-1.5 text-sm shrink-0 cursor-pointer">
            <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
            deep
          </label>
          <Button variant="ghost" size="icon" onClick={() => setDark(!dark)}>
            {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </Button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8">
        {loading && (
          <div className="space-y-4">
            <Skeleton className="h-8 w-64" />
            <div className="flex gap-3">
              {Array.from({ length: 5 }).map((_, n) => (
                <Skeleton key={n} className="h-24 flex-1" />
              ))}
            </div>
            <Skeleton className="h-64 w-full" />
          </div>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!loading && !error && !report && (
          <div className="text-center py-24">
            <Telescope className="size-12 mx-auto mb-4 text-muted-foreground" />
            <h1 className="text-3xl font-semibold">What's it built with?</h1>
            <p className="text-muted-foreground mt-2 max-w-lg mx-auto">
              Point SiteScope at any URL. One fetch tells you the tech stack, how secure its headers and cookies
              are, its certificate and DNS posture, and every resource it loads.
            </p>
            <div className="flex gap-2 justify-center mt-6">
              {["vercel.com", "github.com", "news.ycombinator.com"].map((ex) => (
                <Button
                  key={ex}
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setUrl(ex)
                    run(ex)
                  }}
                >
                  {ex}
                </Button>
              ))}
            </div>
          </div>
        )}

        {report && (
          <Tabs defaultValue="overview">
            <TabsList className="mb-6 flex-wrap h-auto">
              {PAGES.map((p) => (
                <TabsTrigger key={p.id} value={p.id}>
                  {p.label}
                </TabsTrigger>
              ))}
            </TabsList>
            {PAGES.map((p) => (
              <TabsContent key={p.id} value={p.id}>
                {p.render(report)}
              </TabsContent>
            ))}
          </Tabs>
        )}
      </main>
    </div>
  )
}
