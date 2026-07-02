# AppSecMan UI Stack & Tasarım Rehberi

Bu dokümanın amacı: AppSecMan'in görünüş ve hissini başka ürünlerde **aynı şekilde** yeniden üretebilmek. Hangi teknolojiler kullanılıyor, hangi token'lar/renkler, hangi düzen (layout) prensipleri, hangi bileşen pattern'leri — hepsi tek dosyada.

> **AppSecWatch divergence (2026-07):** AppSecWatch'ın `web/` UI'ı bu spec'ten şu
> noktalarda bilinçli olarak ayrıldı — bunlar için `web/src/app/globals.css` +
> `AGENTS.md` esas alınır: **light-first** tema (dark toggle ile), **Geist Sans/Mono**
> (`geist` paketi, `next/font/local`), **tek** desatüre indigo vurgu rengi
> (`--primary`; `--accent` yalnızca shadcn hover-tint semantiği), ve semantik
> durum/severity token'ları (`--success`, `--warning`, `--sev-critical…--sev-info`
> — bileşenlerde hex yok). Aşağıdaki bölümler AppSecMan'i (ana ürünü) tarif eder.

---

## 1. Genel Bakış — Stack özeti

| Katman | Teknoloji | Sürüm |
| --- | --- | --- |
| Framework | **Next.js (App Router)** | ^16.0.10 |
| UI library | **React** | ^19.0.0 |
| Dil | **TypeScript** | ^5 |
| Styling | **Tailwind CSS v4** (`@tailwindcss/postcss`) | ^4 |
| Bileşen kütüphanesi | **shadcn/ui** pattern (kendi `components/ui/`'ımızda) | — |
| Headless primitives | **Radix UI** (28+ paket: dialog, dropdown, popover, select, tabs, toast, …) | latest |
| İkonlar | **lucide-react** (birincil), **@heroicons/react** (ikincil) | ^0.454.0 / ^2.2.0 |
| Variant API | **class-variance-authority** (`cva`) | ^0.7.1 |
| Class merge | **clsx** + **tailwind-merge** → tek `cn()` helper | ^2.1.1 / ^2.5.5 |
| Animasyon util | **tw-animate-css** + custom CSS keyframes | ^1.3.3 |
| Toast | **sonner** | latest |
| Form | **react-hook-form** + **@hookform/resolvers** + **zod** | latest / ^3.10 / ^3.25 |
| Tarih | **date-fns** + **react-day-picker** | ^4.1 / latest |
| Grafik | **recharts** | latest |
| Tablo (data grid yok) | düz `<Table>` (shadcn) | — |
| Carousel | **embla-carousel-react** | latest |
| Resizable | **react-resizable-panels** | latest |
| Drawer (mobil) | **vaul** | latest |
| Komut paleti | **cmdk** | latest |
| OTP input | **input-otp** | latest |
| Markdown render | custom (`MarkdownContent.tsx`) | — |
| Diyagram | **mermaid** | ^11.12.3 |
| PDF / XLSX export | **jspdf**, **jspdf-autotable**, **xlsx**, **pptxgenjs** | — |
| Theme | kendi `theme-provider.tsx` (next-themes API uyumlu) | — |

> **Önemli:** `next-themes` paketi `package.json`'da olsa da kullanılmıyor — `src/components/theme-provider.tsx` kendi mini implementasyonumuz. API'si `next-themes` ile uyumlu (`attribute="class"`, `defaultTheme`, `enableSystem`), `localStorage` ile persist eder.

> **Üretilen raporlar ayrı temalıdır:** Motorun ürettiği `report.html` ve
> `executive.html`, web uygulamasının oklch token sisteminden **bağımsız**, kendi
> içine gömülü (self-contained) CSS değişkenleriyle temalanır
> (`appsecwatch/report/templates/_theme.css.j2`; `data-theme` + `prefers-color-scheme`,
> baskıda açık palet). Tarama detay sayfası bu belgeleri `<iframe>` ile gömer ve
> **Executive** + **PDF indir** bağlantılarını sunar; raporun teması uygulamanınkiyle
> karışmaz.

---

## 2. Görsel kimlik — Renk sistemi

Tüm renkler **oklch** uzayında tanımlı, CSS custom property olarak (`--background`, `--primary`, vs.). `src/app/globals.css` içinde `:root` (light) ve `.dark` (dark) blokları var. Tailwind v4'ün `@theme inline` direktifiyle bu değişkenler `bg-background`, `text-foreground`, `border-border` gibi utility class'larına bağlanıyor.

### 2.1 Renk paleti (token isimleri)

| Token | Anlam | Light değer | Dark değer |
| --- | --- | --- | --- |
| `--background` | Ana sayfa zemini | `oklch(0.96 0.005 260)` | `oklch(0.16 0.008 260)` |
| `--foreground` | Birincil metin | `oklch(0.20 0.01 260)` | `oklch(0.92 0.01 0)` |
| `--card` | Kart zemini | `oklch(0.99 0.003 260)` | `oklch(0.19 0.01 260)` |
| `--popover` | Popover / dropdown | `oklch(0.99 0.003 260)` | `oklch(0.19 0.01 260)` |
| `--primary` | Birincil aksiyon (mavi-mor) | `oklch(0.45 0.18 270)` | `oklch(0.58 0.2 270)` |
| `--secondary` | İkincil yüzey | `oklch(0.92 0.01 260)` | `oklch(0.24 0.015 260)` |
| `--muted` | Sessiz arka plan | `oklch(0.88 0.008 260)` | `oklch(0.30 0.01 260)` |
| `--muted-foreground` | Sessiz metin / placeholder | `oklch(0.45 0.01 260)` | `oklch(0.60 0.01 0)` |
| `--accent` | Vurgu (hover, "positive trend") | `oklch(0.55 0.18 280)` | `oklch(0.36 0.06 270)` |
| `--destructive` | Hata / silme | `oklch(0.62 0.22 25)` | `oklch(0.58 0.2 25)` |
| `--border` | Kenarlık | `oklch(0.88 0.01 260)` | `oklch(0.26 0.015 260)` |
| `--input` | Form input zemini | `oklch(0.94 0.008 260)` | `oklch(0.22 0.01 260)` |
| `--ring` | Focus ring | `oklch(0.45 0.18 270)` | `oklch(0.65 0.22 280)` |
| `--sidebar` | Sidebar zemini | `oklch(0.94 0.005 260)` | `oklch(0.14 0.008 260)` |
| `--chart-1..5` | Grafik renkleri | mavi/turuncu/cyan/yeşil/kırmızı varyantları | — |
| `--radius` | Köşe yuvarlama base | `0.5rem` | (aynı) |

**Hue ailesi:** mavi-mor (260–280). Bütün ekosistem 260° hue civarında nötr gri-mavi + 270–280° mor aksent kullanıyor. Bu, ürünün "kurumsal/güvenli/sakin" hissini veriyor.

### 2.2 Severity / status renkleri (token dışı, semantik sabit)

Dashboard ve listelerde severity için doğrudan hex kullanılıyor:

```ts
// src/app/page.tsx
const CHART_COLORS = {
  critical: "#ff1744",  // kırmızı
  high:     "#ff6d00",  // turuncu
  medium:   "#ffd600",  // sarı
  low:      "#00c853",  // yeşil
  purple:   "#d946ef",
  pink:     "#ec4899",
  blue:     "#0ea5e9",
  cyan:     "#06b6d4",
  teal:     "#14b8a6",
}
```

İkonik göstergelerde de bazen Tailwind palette'i: `text-red-500`, `text-green-500` (örn. TopBar'da "Yeni Test" / "Yeni Zafiyet" ikonları).

### 2.3 Radius

```css
--radius: 0.5rem;            /* lg */
--radius-md: calc(--radius - 2px);   /* 6px */
--radius-sm: calc(--radius - 4px);   /* 4px */
--radius-xl: calc(--radius + 4px);   /* 12px */
```

Kartlar `rounded-xl` (12px), butonlar `rounded-md` (6px), badge `rounded-md`, küçük chip'ler / avatar `rounded-lg`.

---

## 3. Tipografi

- Sistem fontu (`body` üzerinde özel font tanımı yok — tarayıcı varsayılanı).
- `-webkit-font-smoothing: antialiased` ve `-moz-osx-font-smoothing: grayscale` her elemente uygulanıyor (globals.css'de `*` selector).
- Yazı boyutları Tailwind defaults (`text-xs`, `text-sm`, `text-base`, `text-lg`, `text-xl`, `text-3xl`):
  - StatCard değeri: `text-3xl font-bold`
  - Kart başlığı (`ChartCard`): `text-lg font-bold`
  - Body / metin: `text-sm`
  - Yardımcı metin / etiket: `text-xs text-muted-foreground`

> Yeni bir projeye taşırken Inter veya Geist gibi modern bir font eklemek istersek `next/font` ile `layout.tsx` üzerinden geçilebilir. Şu an eklenmemiş.

---

## 4. Layout iskeleti

### 4.1 Root layout (`src/app/layout.tsx`)

```tsx
<html lang="en" suppressHydrationWarning>
  <body suppressHydrationWarning>
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
      <ErrorBoundary>
        <AuthProvider>
          <div className="flex h-screen bg-background">
            <LayoutWrapper>
              <ErrorBoundary>{children}</ErrorBoundary>
            </LayoutWrapper>
          </div>
        </AuthProvider>
      </ErrorBoundary>
    </ThemeProvider>
  </body>
</html>
```

Önemli detaylar:
- `suppressHydrationWarning` hem `<html>` hem `<body>`'de (theme class farkı yüzünden).
- `defaultTheme="dark"` — ürün **dark-first**.
- Tüm sayfa `h-screen` + flex container.

### 4.2 Uygulama içi layout (`layout-wrapper.tsx`)

```
┌────────────┬────────────────────────────────────┐
│            │  TopBar (sticky, h-auto)           │
│  Sidebar   ├────────────────────────────────────┤
│  (w-64)    │                                    │
│            │  <main scrollable, p-6>            │
│            │     {children}                     │
│            │                                    │
└────────────┴────────────────────────────────────┘
                      ChatWidget (floating)
```

- **Sidebar:** `w-64` (256px), fixed solda, md+'da `relative`. Mobilde `translate-x` ile slide-in + dim overlay.
- **TopBar:** `sticky top-0 z-20`, alt border'lı.
- **İçerik bölgesi:** `flex-1 overflow-y-auto p-6`.
- **ChatWidget:** floating asistan butonu (sağ-alt).
- Login sayfasında layout uygulanmaz (`pathname === "/login"` ise children doğrudan render).
- Auth loading state'inde merkezde spinner (`h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent`).

### 4.3 Sidebar pattern (`src/components/sidebar.tsx`)

- Logo + ürün adı en üstte (`h-10 w-10` logo + `font-bold text-lg`).
- Menü item'lar: ikon (lucide) + label, `rounded-lg px-4 py-2.5`.
- Active state: `bg-accent/20 text-accent font-medium`.
- Hover: `hover:bg-accent/10 hover:text-foreground`.
- Alt kısımda ayrılmış admin bölümü + Logout (Logout hover'ı `hover:bg-destructive/10 hover:text-destructive`).

### 4.4 TopBar pattern (`src/components/topbar.tsx`)

- Sol: mobil menü butonu (md+'da gizli) + arama input'u.
- Sağ: hızlı aksiyon ikonları (yeni test, yeni zafiyet — renkli ikonlar) + bildirim dropdown + tema toggle + kullanıcı menüsü.
- Kullanıcı avatarı: `rounded-lg bg-gradient-to-br from-primary to-accent` (foto yoksa initials).

---

## 5. Bileşen kütüphanesi (`src/components/ui/`)

shadcn/ui pattern: bileşenler kopyalanır, biz sahibiz, istediğimiz gibi tweak ederiz. Mevcut bileşenler:

```
accordion, alert-dialog, alert, aspect-ratio, avatar, badge, breadcrumb,
button-group, button, calendar, card, carousel, chart, checkbox, collapsible,
command, context-menu, dialog, drawer, dropdown-menu, empty, field, form,
hover-card, input-group, input-otp, input, item, kbd, label, menubar,
navigation-menu, pagination, popover, progress, radio-group, scroll-area,
select, separator, sheet, sidebar, skeleton, slider, sonner, spinner, switch,
table, tabs, textarea, toast, toaster, toggle-group, toggle, tooltip
```

### 5.1 Button — kanonik örnek

`cva` ile variant + size, `Slot` ile `asChild` desteği:

```ts
// 6 variant: default | destructive | outline | secondary | ghost | link
// 6 size:    default | sm | lg | icon | icon-sm | icon-lg
<Button variant="outline" size="sm">Filter</Button>
<Button asChild><Link href="/new">Yeni</Link></Button>
```

Önemli detay: tüm interaktif elemanlarda `focus-visible:ring-ring/50 focus-visible:ring-[3px]` ve `aria-invalid:ring-destructive/20` standardı.

### 5.2 Card — kanonik konteyner

```tsx
<Card className="p-6 border border-border">
  <CardHeader>
    <CardTitle>Başlık</CardTitle>
    <CardDescription>Açıklama</CardDescription>
  </CardHeader>
  <CardContent>...</CardContent>
</Card>
```

Default class: `bg-card text-card-foreground flex flex-col gap-6 rounded-xl border py-6 shadow-sm`.

### 5.3 Badge

4 variant: `default | secondary | destructive | outline`. Severity için biz `outline` + custom class kullanıyoruz, ya da inline `style={{ backgroundColor: CHART_COLORS.high }}`.

### 5.4 Form pattern

```tsx
const form = useForm({ resolver: zodResolver(schema) })
<Form {...form}>
  <FormField name="email" control={form.control} render={({ field }) => (
    <FormItem>
      <FormLabel>E-posta</FormLabel>
      <FormControl><Input {...field} /></FormControl>
      <FormMessage />
    </FormItem>
  )}/>
</Form>
```

### 5.5 Toast / bildirim

İki paralel sistem var (legacy + yeni):
- **sonner** (`<Sonner />`, `toast.success(...)`) → yeni kod.
- **`use-toast`** + `<Toaster />` (shadcn radix toast) → eski kod.

Yeni projelerde sadece `sonner` öneririm.

---

## 6. Tekrar eden uygulama-seviyesi bileşenler (`src/components/`)

| Bileşen | Amaç | Anahtar görsel imza |
| --- | --- | --- |
| `StatCard` | KPI kartı (sayı + ikon + trend) | `text-3xl font-bold`, sağ üstte `h-12 w-12 rounded-lg bg-accent/15` ikon kutusu, hover'da `hover:border-accent/50 hover:shadow-lg hover:shadow-accent/10` |
| `ChartCard` | Recharts wrapper | Card + `text-lg font-bold mb-6` başlık |
| `ActivityItem` | Aktivite akış satırı | Avatar + metin + zaman |
| `Sidebar` | Yan menü | Bölüm 4.3 |
| `TopBar` | Üst bar | Bölüm 4.4 |
| `ChatWidget` | Floating asistan | sağ-alt köşede sabit |
| `NotificationsDropdown` | Bildirim popover | TopBar içinde, unread badge'lı |
| `ChangelogModal` | Sürüm notu modalı | login sonrası açılır |
| `ChangePasswordModal` | Şifre değiştir | Dialog tabanlı |
| `MarkdownContent` | İçerideki MD render | custom CSS (globals.css'deki `.markdown-content` sınıfları) |
| `MermaidDiagram` | Mermaid render | tema-aware |
| `ErrorBoundary` | Hata sınırı | toplu kullanım |
| `LoadingSpinner` | Yüklenme | `animate-spin` + primary border |
| `theme-provider` | Light/dark | Bölüm 8 |

---

## 7. Stil pattern'leri (ezberlenmesi gereken)

### 7.1 `cn()` helper — zorunlu

```ts
// src/lib/utils.ts
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
```

Her dinamik className birleştirmesi `cn(...)` ile yapılır — yoksa `tailwind-merge` çakışmaları çözmez.

### 7.2 Glassmorphism

```css
.glass         { @apply bg-card/40 backdrop-blur-md border border-border; }
.glass-strong  { @apply bg-card/70 backdrop-blur-md border border-border; }
```

### 7.3 Animasyonlar

`globals.css` içinde tanımlı custom utility'ler:

```
.animate-fade-in-up      → 0.5s ease-out fadeInUp
.animate-slide-in-left   → 0.5s ease-out slideInLeft
.animate-delay-100..400  → staggered animation-delay
.transition-smooth       → transition-all duration-300 ease-out
```

Pattern: liste item'larına `delay={index * 100}` veriyoruz, sırayla "açılma" efekti.

### 7.4 Hover prensibi

- Buton/Card hover'da: `hover:shadow-md` + dark'ta `dark:hover:brightness-110`.
- Tıklanabilir kart: border + shadow accent rengiyle vurgulanır:
  `hover:border-accent/50 hover:shadow-lg hover:shadow-accent/10`.

### 7.5 Spacing

- Sayfa içi padding: `p-6` (24px).
- Kart içi padding: `p-6`.
- Form gap: `gap-4` veya `gap-6`.
- Liste item arası: `space-y-1` (sidebar), `space-y-2` (kart listeleri).

### 7.6 Z-index hiyerarşisi

| Katman | z |
| --- | --- |
| Mobile sidebar overlay | `z-30` |
| Mobile sidebar panel | `z-40` |
| TopBar (sticky) | `z-20` |
| Dropdown / popover | Radix yönetir |
| Toast | Sonner yönetir (en üst) |

---

## 8. Tema yönetimi (`theme-provider.tsx`)

Kendi minimal provider'ımız (next-themes paketini import etmiyor ama API'sini taklit ediyor):

- `<html class="dark">` veya `<html class="light">` set eder + `style.colorScheme` ayarlar.
- `localStorage["theme"]` ile persist.
- `enableSystem` ile sistem tercihi başlangıç olarak okunur ama kullanıcı seçimi her zaman override eder.
- `useTheme()` hook'u — provider dışında çağrılırsa "dark" döner (test güvenliği için).
- Default: **`dark`**. Yeni ürünlerde light istiyorsanız `defaultTheme="light"`.

---

## 9. Sayfa örnek pattern'i (dashboard)

`src/app/page.tsx` örneği:

```tsx
'use client'
// 1) StatCard grid (KPI'lar)
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
  <StatCard title="..." value={123} icon={Shield} delay={0} />
  <StatCard title="..." value={45}  icon={AlertCircle} delay={100} />
  ...
</div>

// 2) Recharts grafikleri ChartCard içinde
<div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-6">
  <ChartCard title="Severity dağılımı">
    <ResponsiveContainer><PieChart>...</PieChart></ResponsiveContainer>
  </ChartCard>
</div>
```

Tipik grid kırılım noktaları: `grid-cols-1 md:grid-cols-2 lg:grid-cols-4`.

---

## 10. İkonlar

- **Birincil:** `lucide-react` — sidebar, topbar, aksiyon butonları.
- Tipik boyut: `h-4 w-4` (buton içi), `h-5 w-5` (sidebar/topbar), `h-6 w-6` (StatCard ikon kutusu).
- Heroicons da kurulu ama çok az kullanılıyor.

İsim örnekleri (sidebar): `LayoutDashboard, Package, Flag, AlertTriangle, BarChart3, Settings, LogOut, Target, Mail, ShieldCheck`.

---

## 11. Yeni bir projede aynı görünüşü kurmak — adım adım checklist

### 11.1 Bağımlılıklar

```bash
# Framework
npm i next@^16 react@^19 react-dom@^19 typescript

# Tailwind v4
npm i -D tailwindcss@^4 @tailwindcss/postcss tw-animate-css autoprefixer

# shadcn temel taşları
npm i class-variance-authority clsx tailwind-merge

# Radix primitives (ihtiyaca göre)
npm i @radix-ui/react-slot @radix-ui/react-dialog @radix-ui/react-dropdown-menu \
      @radix-ui/react-popover @radix-ui/react-select @radix-ui/react-tabs \
      @radix-ui/react-tooltip @radix-ui/react-toast @radix-ui/react-checkbox \
      @radix-ui/react-switch @radix-ui/react-separator @radix-ui/react-label \
      @radix-ui/react-avatar

# UI extras
npm i lucide-react sonner recharts react-hook-form @hookform/resolvers zod \
      date-fns react-day-picker cmdk vaul embla-carousel-react \
      react-resizable-panels input-otp
```

### 11.2 Dosya iskeleti

```
src/
├── app/
│   ├── globals.css           ← bu repo'daki dosyayı KOPYALA
│   ├── layout.tsx            ← bu repo'daki layout pattern
│   └── layout-wrapper.tsx    ← Sidebar+TopBar wrapper
├── components/
│   ├── ui/                   ← shadcn bileşenlerini buraya koy
│   ├── theme-provider.tsx
│   ├── sidebar.tsx
│   └── topbar.tsx
├── lib/
│   └── utils.ts              ← cn() helper
└── contexts/
    └── AuthContext.tsx       ← (opsiyonel)
```

### 11.3 `postcss.config.mjs`

```js
const config = { plugins: ["@tailwindcss/postcss"] };
export default config;
```

### 11.4 `globals.css`

Bu repodaki `src/app/globals.css` dosyasını birebir kopyala. İçinde:
- `@import "tailwindcss"` + `@import "tw-animate-css"`
- `@custom-variant dark`
- `:root` ve `.dark` token blokları
- `@theme inline` ile token → Tailwind utility eşlemesi
- `.glass`, `.transition-smooth`, custom keyframes, `.markdown-content` stilleri

> **Bu dosya = ürünün görsel kimliği.** Renkleri değiştirmek istersen sadece `--primary`, `--accent` ve `--background` üzerinde oyna; geri kalan token'lar otomatik uyum sağlar.

### 11.5 `theme-provider.tsx`

Bu repodaki dosyayı birebir kopyala. `next-themes` paketine **ihtiyaç yok** — bu kendi minimal versiyonumuz.

### 11.6 Layout sırası

```tsx
<ThemeProvider defaultTheme="dark">
  <AuthProvider>
    <div className="flex h-screen bg-background">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <TopBar />
        <div className="flex-1 overflow-y-auto p-6">{children}</div>
      </div>
    </div>
  </AuthProvider>
</ThemeProvider>
```

### 11.7 shadcn bileşenlerini kurma

İki yol:
- **Önerilen:** Bu repo'daki `src/components/ui/*` dosyalarını birebir kopyala (zaten bizim tweak'larımızı içeriyor — ör. Button'da `dark:hover:brightness-110`).
- **Alternatif:** `npx shadcn@latest init` + ihtiyaç duydukça `npx shadcn@latest add button card dialog ...`. Bu yol "vanilla" shadcn verir; bizim ince ayarlarımız olmaz.

---

## 12. "AppSecMan look" — özet rehber kart

Bir başka ürünü AppSecMan'e benzetmek için yapılacaklar (öncelik sırasıyla):

1. **Dark-first tema:** `<ThemeProvider defaultTheme="dark">`.
2. **Token paleti:** `globals.css`'i kopyala, `--primary` ve `--accent` mor-mavi tonlarında tut (270–280 hue).
3. **Layout:** sol 256px sabit sidebar (logo+menü+admin+logout), üstte sticky topbar (arama+aksiyonlar+tema+kullanıcı).
4. **Kartlar:** `rounded-xl`, `border-border`, hover'da `border-accent/50 + shadow-accent/10`.
5. **KPI:** `StatCard` pattern'i — sayı `text-3xl font-bold`, sağ üstte `h-12 w-12 rounded-lg bg-accent/15` ikon kutusu.
6. **Aksiyon butonları:** lucide ikon + Türkçe label, sidebar'da `rounded-lg px-4 py-2.5`, active `bg-accent/20 text-accent`.
7. **Tipografi:** sistem fontu, antialiased, `text-sm` body, `text-lg font-bold` kart başlığı.
8. **Animasyon:** liste item'larına `animate-fade-in-up` + 100ms stagger.
9. **Severity renkleri:** kırmızı `#ff1744` / turuncu `#ff6d00` / sarı `#ffd600` / yeşil `#00c853` — sadece dashboard ve grafiklerde.
10. **Toast:** sonner (sağ üst).

---

## 13. Sık karşılaşılan tuzaklar

- **`cn()` kullanmazsan** `tailwind-merge` çalışmaz, `className="p-4 p-6"` ikisini de uygular → görsel bug.
- **`suppressHydrationWarning` koymazsan** dark theme class'ı SSR/CSR farkı yüzünden hydration hatası verir.
- **Radix primitiflerini direkt kullanma** — daima `components/ui/` üzerinden geç (focus ring, aria-invalid pattern'i kayıyor).
- **`next-themes` kurma** — bizim provider'ımız var, çift implementasyon çakışır.
- **Tailwind v3 syntax'i kullanma** — v4'te `@theme inline` ve `@custom-variant` var, `tailwind.config.ts` artık opsiyonel (bizde yok).
- **shadcn `npx add` ile gelen Button'u kopyala-yapıştır kullanma** — bizim Button'da `dark:hover:brightness-110` ve 6 size variant var, vanilla shadcn'de 4 size.

---

## 14. Referans dosyalar (bu repo'da)

| Konu | Dosya |
| --- | --- |
| Token paleti & global stiller | [src/app/globals.css](src/app/globals.css) |
| Root layout | [src/app/layout.tsx](src/app/layout.tsx) |
| App shell (Sidebar+TopBar wrapper) | [src/app/layout-wrapper.tsx](src/app/layout-wrapper.tsx) |
| Sidebar | [src/components/sidebar.tsx](src/components/sidebar.tsx) |
| TopBar | [src/components/topbar.tsx](src/components/topbar.tsx) |
| Theme provider | [src/components/theme-provider.tsx](src/components/theme-provider.tsx) |
| `cn()` helper | [src/lib/utils.ts](src/lib/utils.ts) |
| Button (kanonik cva örneği) | [src/components/ui/button.tsx](src/components/ui/button.tsx) |
| Card | [src/components/ui/card.tsx](src/components/ui/card.tsx) |
| Badge | [src/components/ui/badge.tsx](src/components/ui/badge.tsx) |
| StatCard | [src/components/stat-card.tsx](src/components/stat-card.tsx) |
| ChartCard | [src/components/chart-card.tsx](src/components/chart-card.tsx) |
| Dashboard örnek sayfa | [src/app/page.tsx](src/app/page.tsx) |
| PostCSS config | [postcss.config.mjs](postcss.config.mjs) |
| Bağımlılıklar | [package.json](package.json) |

---

## 15. TL;DR

> **AppSecMan = Next.js 16 + React 19 + Tailwind v4 (oklch token tabanlı) + shadcn/ui (Radix primitives) + lucide ikonlar + dark-first tema. Mor-mavi (hue 260–280) kurumsal palet, sol 256px sidebar + sticky topbar layout, `rounded-xl` kartlar, `text-3xl font-bold` KPI'lar, sonner toast, recharts grafik.**
>
> Aynı görünüşü başka bir projeye getirmek için: bağımlılıkları kur, `globals.css` + `theme-provider.tsx` + `lib/utils.ts` + `components/ui/*` dosyalarını birebir kopyala, layout'u Bölüm 4'teki iskelete oturt. Renk değiştirmek istersen sadece `--primary`/`--accent` token'larını oyna.
 
