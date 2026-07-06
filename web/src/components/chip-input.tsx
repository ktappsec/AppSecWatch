"use client";

// Token/chip multiselect for large target lists (the New-Scan "assets" mode).
// Parses a newline/comma/space-separated string into deduped chips with a live
// count, per-item remove, search-to-add, and collapse past a threshold — so a
// 400-domain selection stays manageable instead of a raw textarea blob.
import * as React from "react";
import { X, Plus } from "lucide-react";
import { cn } from "@/lib/utils";

const SPLIT = /[\s,]+/;
const COLLAPSE_AT = 12;

function parse(value: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of value.split(SPLIT)) {
    const t = raw.trim().toLowerCase();
    if (t && !seen.has(t)) { seen.add(t); out.push(t); }
  }
  return out;
}

export function ChipInput({
  value, onChange, placeholder = "app.example.com",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  const items = React.useMemo(() => parse(value), [value]);
  const [draft, setDraft] = React.useState("");
  const [showAll, setShowAll] = React.useState(false);

  const commit = (next: string[]) => onChange(next.join("\n"));

  const addDraft = () => {
    const toks = parse(draft);
    if (!toks.length) { setDraft(""); return; }
    const merged = [...items];
    for (const t of toks) if (!merged.includes(t)) merged.push(t);
    commit(merged);
    setDraft("");
  };
  const remove = (t: string) => commit(items.filter((x) => x !== t));

  const shown = showAll ? items : items.slice(0, COLLAPSE_AT);

  return (
    <div className="space-y-2">
      <div className="flex min-h-[42px] flex-wrap items-center gap-1.5 rounded-lg border border-border bg-background p-2">
        {shown.map((t) => (
          <span key={t} className="inline-flex items-center gap-1 rounded-md bg-secondary px-1.5 py-0.5 font-mono text-[11px]">
            {t}
            <button type="button" onClick={() => remove(t)} aria-label={`remove ${t}`} className="opacity-60 hover:opacity-100">
              <X className="h-2.5 w-2.5" />
            </button>
          </span>
        ))}
        {items.length > COLLAPSE_AT && (
          <button type="button" onClick={() => setShowAll((s) => !s)}
            className="rounded-md border border-dashed border-border px-1.5 py-0.5 text-[11px] text-muted-foreground hover:text-foreground">
            {showAll ? "show fewer" : `+${items.length - COLLAPSE_AT} more`}
          </button>
        )}
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") { e.preventDefault(); addDraft(); }
            else if (e.key === "Backspace" && !draft && items.length) remove(items[items.length - 1]);
          }}
          onBlur={addDraft}
          onPaste={(e) => {
            // Bulk paste (e.g. 400 fqdns): parse the pasted blob straight into chips.
            const text = e.clipboardData.getData("text");
            if (SPLIT.test(text.trim())) {
              e.preventDefault();
              const merged = [...items];
              for (const t of parse(text)) if (!merged.includes(t)) merged.push(t);
              commit(merged);
            }
          }}
          placeholder={items.length ? "add…" : placeholder}
          className={cn("min-w-[120px] flex-1 bg-transparent px-1 font-mono text-xs outline-none placeholder:text-muted-foreground")}
        />
      </div>
      {items.length > 0 && (
        <p className="text-[11px] text-muted-foreground">
          {items.length} target{items.length === 1 ? "" : "s"} selected. Type or paste to add; Enter / comma commits.
        </p>
      )}
    </div>
  );
}
