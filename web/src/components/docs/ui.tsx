// Shared, language-agnostic presentational primitives for the docs pages.
// All visible text is supplied via props, so the English (`/docs`) and Turkish
// (`/docs/tr`) pages reuse these without duplication; only prose + diagram
// labels live in the page files.
import { cn } from "@/lib/utils";

export function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20 space-y-3">
      <h2 className="border-b border-border pb-2 text-xl font-bold">{title}</h2>
      <div className="space-y-3 text-sm leading-relaxed text-muted-foreground [&_strong]:text-foreground">
        {children}
      </div>
    </section>
  );
}

export function Mono({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-secondary px-1 py-0.5 font-mono text-[0.85em] text-foreground">{children}</code>;
}

export function Badge({ tone, children }: { tone: "good" | "muted"; children: React.ReactNode }) {
  return (
    <span className={
      tone === "good"
        ? "rounded border border-[#00c853]/40 px-1.5 py-0.5 font-mono text-[11px] text-[#00c853]"
        : "rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground"
    }>
      {children}
    </span>
  );
}

export function Callout({ children, tone = "info" }: { children: React.ReactNode; tone?: "info" | "warn" }) {
  return (
    <div className={cn(
      "rounded-lg border-l-2 px-3 py-2 text-sm",
      tone === "warn"
        ? "border-l-[#ff6d00] bg-[#ff6d00]/5 text-muted-foreground"
        : "border-l-accent bg-accent/5 text-muted-foreground",
    )}>
      {children}
    </div>
  );
}

export function Figure({ caption, children }: { caption: string; children: React.ReactNode }) {
  return (
    <figure className="space-y-2 rounded-lg border border-border bg-card/50 p-4">
      <div>{children}</div>
      <figcaption className="text-[11px] leading-snug text-muted-foreground">{caption}</figcaption>
    </figure>
  );
}

export function FlowNode({ title, sub, tone = "default", className }: {
  title: string; sub?: string; tone?: "default" | "accent"; className?: string;
}) {
  return (
    <div className={cn(
      "flex min-w-[8rem] flex-col gap-0.5 rounded-lg border px-3 py-2 text-center",
      tone === "accent" ? "border-accent/50 bg-accent/5" : "border-border bg-card",
      className,
    )}>
      <span className="text-xs font-semibold text-foreground">{title}</span>
      {sub && <span className="text-[10px] leading-tight text-muted-foreground">{sub}</span>}
    </div>
  );
}

export function Arrow({ dir = "right" }: { dir?: "right" | "down" }) {
  return (
    <span aria-hidden className="shrink-0 select-none text-base text-muted-foreground/50">
      {dir === "right" ? "→" : "↓"}
    </span>
  );
}

/** EN / TR language switch shown in each docs page header. */
export function DocsLangToggle({ active }: { active: "en" | "tr" }) {
  const opts: { code: "en" | "tr"; label: string; href: string }[] = [
    { code: "en", label: "EN", href: "/docs" },
    { code: "tr", label: "TR", href: "/docs/tr" },
  ];
  return (
    <div className="flex gap-1" role="group" aria-label="Documentation language">
      {opts.map((o) => (
        <a key={o.code} href={o.href} aria-current={active === o.code ? "page" : undefined}
          className={cn(
            "rounded-md border px-2.5 py-1 text-xs font-medium transition-smooth",
            active === o.code
              ? "border-accent/50 bg-accent/10 text-accent"
              : "border-border text-muted-foreground hover:border-accent/40 hover:text-accent",
          )}>
          {o.label}
        </a>
      ))}
    </div>
  );
}
