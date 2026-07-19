// the report object is large and loosely shaped — it comes straight from the
// node analyzers. typing every field would be busywork, so the pages read it
// defensively instead.
export type Report = Record<string, any>

export async function scan(url: string, deep: boolean): Promise<Report> {
  const qs = new URLSearchParams({ url })
  if (deep) {
    qs.set("ports", "1")
    qs.set("paths", "1")
    qs.set("subs", "1")
  }
  const res = await fetch("/api/analyze?" + qs)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || res.statusText)
  return data
}

// score bands, matching the vanilla ui so both read the same
export const tone = (n: number) => (n >= 70 ? "ok" : n >= 45 ? "warn" : "bad")

export const gradeTone = (g: string) =>
  g === "A" || g === "B" ? "ok" : g === "C" ? "warn" : "bad"

export const sevIcon = (sev: string) =>
  ({ critical: "🛑", high: "🔴", medium: "🟠", low: "🟡", info: "⚪" }[sev] || "•")

// badge variant per severity, so the table reads at a glance
export const sevVariant = (sev: string): "destructive" | "secondary" | "outline" =>
  sev === "critical" || sev === "high" ? "destructive" : sev === "medium" ? "secondary" : "outline"

export function fmtBytes(n?: number) {
  if (n == null) return "—"
  const u = ["B", "KB", "MB", "GB"]
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`
}
