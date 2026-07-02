import { Fragment } from "react";
import type { Metadata } from "next";
import { Card } from "@/components/ui/card";
import { CAPABILITY_TOKENS, THROTTLE_PROFILES } from "@/lib/constants";
import { Arrow, Badge, Callout, DocsLangToggle, Figure, FlowNode, Mono, Section } from "@/components/docs/ui";

export const metadata: Metadata = {
  title: "Dokümanlar · AppSecWatch",
  description: "AppSecWatch nasıl tarar, sınıflandırır ve raporlar.",
};

const TOC: { id: string; label: string }[] = [
  { id: "overview", label: "Nasıl çalışır" },
  { id: "recon", label: "Keşif ve yeniden besleme döngüsü" },
  { id: "liveness", label: "Canlı vs ölü varlıklar" },
  { id: "audit", label: "Denetim dağılımı" },
  { id: "ai", label: "Yapay zekâ analizi" },
  { id: "profiling", label: "Profilleme ve yakalama" },
  { id: "throttle", label: "Hız sınırlama kademeleri" },
  { id: "identity", label: "Gizli kimlik" },
  { id: "tls", label: "TLS karnesi" },
  { id: "suppression", label: "Bastırma" },
  { id: "first-scan", label: "İlk taramanız" },
  { id: "scheduling", label: "Zamanlama" },
  { id: "capabilities", label: "Yetenek referansı" },
];

const THROTTLE_NOTES: Record<string, string> = {
  paranoid: "~seri, çok düşük hızlar, uzun beklemeler — sertleştirilmiş / WAF'lı hedeflere karşı maksimum gizlilik (httpx thread 1).",
  gentle: "Düşük hızlar, httpx thread 2 — patlama trafiğini engelleyen sertleştirilmiş hedefler için güvenli seçim.",
  normal: "Varsayılan — araçların kendi varsayılanlarına eşit dengeli hızlar (httpx thread 10).",
  aggressive: "Tamamen sizin kontrolünüzdeki hedefler için yüksek eşzamanlılık (httpx thread 50).",
  insane: "En hızlı ve en gürültülü (httpx thread 200) — WAF'ları KESİNLİKLE tetikler.",
};

// Kademe başına tam ayar değerleri — appsecwatch/config.py `_PROFILES` ile birebir.
const THROTTLE_DETAIL: {
  tier: string; httpx: string; nuclei: number; takeovers: number; dnsx: number; tlsx: number; tls: string; conc: string;
}[] = [
  { tier: "paranoid", httpx: "2 / 1", nuclei: 2, takeovers: 2, dnsx: 50, tlsx: 5, tls: "900 sn", conc: "1 / 1 / 1" },
  { tier: "gentle", httpx: "10 / 2", nuclei: 10, takeovers: 10, dnsx: 100, tlsx: 20, tls: "600 sn", conc: "3 / 2 / 2" },
  { tier: "normal", httpx: "100 / 10", nuclei: 100, takeovers: 50, dnsx: 1000, tlsx: 100, tls: "300 sn", conc: "10 / 5 / 5" },
  { tier: "aggressive", httpx: "500 / 50", nuclei: 500, takeovers: 150, dnsx: 5000, tlsx: 300, tls: "180 sn", conc: "20 / 10 / 8" },
  { tier: "insane", httpx: "1000 / 200", nuclei: 1000, takeovers: 300, dnsx: 10000, tlsx: 500, tls: "120 sn", conc: "40 / 20 / 15" },
];

// Gizli kimlik profilleri — appsecwatch/config.py `IDENTITY_PRESETS` ile birebir.
const IDENTITY_PRESETS: { name: string; ua: string; platform: string; hints: string; isDefault?: boolean }[] = [
  { name: "chrome-win", ua: "Chrome/149 · Windows NT 10.0", platform: '"Windows"', hints: "yalnızca düşük entropili", isDefault: true },
  { name: "chrome-mac", ua: "Chrome/149 · Intel Mac OS X 10_15_7", platform: '"macOS"', hints: "yalnızca düşük entropili" },
  { name: "firefox", ua: "Firefox/140 · Windows", platform: "—", hints: "yok (Firefox'ta UA-CH yok)" },
  { name: "off", ua: "her aracın kendi varsayılanı", platform: "—", hints: "enjekte başlık / referrer yok" },
];

const REFERER_POOL = [
  "google.com", "google.com.tr", "bing.com", "duckduckgo.com", "search.yahoo.com",
  "yandex.com.tr", "facebook.com", "linkedin.com", "t.co", "reddit.com",
];

export default function DocsPageTR() {
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <header className="space-y-2">
        <div className="flex items-start justify-between gap-4">
          <h1 className="text-3xl font-bold">AppSecWatch dokümantasyonu</h1>
          <DocsLangToggle active="tr" />
        </div>
        <p className="text-sm text-muted-foreground">
          AppSecWatch, anlık (point-in-time) harici bir{" "}
          <span className="font-medium">Katman-7 AppSec</span> denetim orkestratörüdür. Her tarama
          eksiksiz, bağımsız bir çıktı seti üretir — veritabanı yoktur ve koşular arasında durum
          taşınmaz.
        </p>
      </header>

      {/* TOC */}
      <Card className="p-4">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Bu sayfada
        </p>
        <nav className="flex flex-wrap gap-2">
          {TOC.map((t) => (
            <a key={t.id} href={`#${t.id}`}
              className="rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground transition-smooth hover:border-primary/40 hover:text-primary">
              {t.label}
            </a>
          ))}
        </nav>
      </Card>

      <Section id="overview" title="Nasıl çalışır">
        <p>
          Bir tarama, modüler ve asenkron bir hat (pipeline) çalıştırır. Ona bir veya birden çok{" "}
          <strong>kök alan adı</strong> (ya da kayıtlı bir varlık grubu) verirsiniz. Yapılandırılan
          kökler <strong>tek</strong> kapsamdır — bir kök altında çözümlenen her ad, nerede
          barındırıldığına bakılmaksızın taranır.
        </p>
        <Figure caption="Bir taramanın beş aşaması. Keşif her zaman önce çalışır; denetim düğümleri paralel dağılır; yapay zekâ katmanı denetimden sonra çalışır ki tarayıcının render edilmiş yakalamasını okuyabilsin.">
          <PipelineDiagram />
        </Figure>
        <p>
          Bir taramanın ürettiği her şey <Mono>runs/&lt;id&gt;/</Mono> altına düşer: ham araç çıktısı
          (<Mono>01_recon/</Mono>, <Mono>02_audit/</Mono>, <Mono>03_ai/</Mono>), birleştirilmiş{" "}
          <Mono>result.json</Mono>, bir <Mono>errors.json</Mono> / <Mono>summary.json</Mono> özeti ve
          tek dosyalık iki belge (CSS/JS gömülü — e-postayla paylaşıma dayanır): tam teknik{" "}
          <Mono>report.html</Mono> ve yönetici özeti tek-sayfalık <Mono>executive.html</Mono> (artı
          isteğe bağlı <Mono>executive.pdf</Mono>), her ikisinde de açık/koyu tema düğmesi.
          Web arayüzü aynı motorun üzerinde ince bir katmandır ve koşular-arası ilişkisel bir katman
          (varlıklar, zamanlamalar, bastırmalar, geçmiş) ekler; bunlar SQLite'ta tutulur. Tamamlanan
          bir tarama, kayıtlı hatalar olsa bile <Mono>0</Mono> ile çıkar; <Mono>--strict</Mono>
          herhangi bir başarısızlığı CI için sıfır-olmayan bir çıkışa çevirir.
        </p>
      </Section>

      <Section id="recon" title="Keşif ve yeniden besleme döngüsü">
        <p>
          Keşif <strong>omurgası</strong> sırayla çalışır ve diğer her yetenek için her zaman bir ön
          koşuldur. Neyin var olduğunu ve neyin canlı olduğunu belirler, ardından her alt düğümü
          besler.
        </p>
        <Figure caption="Keşif omurgası. Canlı sertifikalar, köklere göre filtrelenen Subject-Alternative-Name (SAN) adlarını toplar; bunlar dnsx'e geri beslenir ve kapsamı en fazla 3 yineleme boyunca genişletir.">
          <ReconFlow />
        </Figure>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><strong>subfinder</strong> — pasif alt alan keşfi. <em>İsteğe bağlı</em>: verdiğiniz tam köklerin/varlıkların hızlı bir denetimi için atlayın (zorunlu taban <Mono>dns</Mono> + <Mono>httpx</Mono>'tir).</li>
          <li><strong>dnsx</strong> — her adayı çözer (A + CNAME, IPv4). Kökler her zaman tohumlanır, böylece subfinder olmayan bir tarama da onları çözer.</li>
          <li><strong>tlsx yeniden besleme</strong> — tek bir el sıkışma iki iş yapar: sertifika SAN'larını toplar (dnsx'e geri beslenir, 3 yinelemeyle sınırlı; <Mono>*.</Mono> joker karakterler kaydedilir ama yinelenmez) <em>ve</em> pasif bir <strong>sertifika dosyası</strong> yakalar (veren, son kullanma, seri, SHA-256, kendinden imzalı / joker) — yalnızca envanter, Certs sekmesinde gösterilir.</li>
          <li><strong>httpx</strong> — canlı web sunucularını ayıklar ve <Mono>-include-response</Mono> ile her host için <strong>PageSignals</strong> üretir (başlık, meta / OpenGraph, JS öncesi gövde parçası, form sinyalleri, tespit edilen teknolojiler) — daha zengin bir tarama yokken profilleyici bunu kullanır.</li>
        </ul>
      </Section>

      <Section id="liveness" title="Canlı vs ölü varlıklar">
        <p>
          AppSecWatch keşfedilen her adı tek bir <strong>canlılık</strong> ekseninde sınıflandırır —
          sahiplik / “kapsam-içi vs gölge-BT” kovalaması yoktur. Bir L7 denetimi için önemli olan,
          hostun yanıt verip vermediğidir; IP'sini hangi ağın barındırdığı değil.
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <Badge tone="good">canlı</Badge> — bir veya daha fazla A kaydına çözümlenir. Tamamen
            taranır ve sertifika SAN'ları, kapsamı genişletmek için DNS → TLS yeniden keşif
            döngüsüne geri beslenir.
          </li>
          <li>
            <Badge tone="muted">ölü</Badge> — NXDOMAIN veya A kaydı yok (ör. sarkan bir{" "}
            <Mono>CNAME</Mono>). Aktif taranmaz, ancak çevrimdışı sağlayıcı-parmak izi DB'si
            üzerinden <a href="#audit" className="text-primary hover:underline">alt alan ele
            geçirme</a> için izlenir.
          </li>
        </ul>
        <p>
          ASN / kuruluş yalnızca <strong>gösterim amaçlı zenginleştirmedir</strong>. Bunun için
          isteğe bağlı bir MaxMind GeoLite2-ASN MMDB gerekir (Ayarlar'da yapılandırılır); o olmadan
          taramalar tıpatıp aynı çalışır, sadece ASN sütunu olmaz. Bir taramayı asla geçitlemez.
        </p>
      </Section>

      <Section id="audit" title="Denetim dağılımı">
        <p>
          Canlı küme üzerinde beş bağımsız yetenek paralel çalışır (ölü küme yalnızca çevrimdışı ele
          geçirme kontrolünü besler). Her biri eşzamanlılık sınırlarıyla ve seçilen{" "}
          <a href="#throttle" className="text-primary hover:underline">hız kademesiyle</a> sınırlıdır.
        </p>
        <Figure caption="Denetim aşaması. Beş düğüm eşzamanlı çalışır; hiçbiri diğerine bağlı değildir.">
          <AuditFanout />
        </Figure>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><strong>Ele geçirmeler</strong> — iki yarım: CNAME zinciri kökleri terk eden canlı hostlar <Mono>nuclei -t http/takeovers/</Mono> ile kontrol edilir; ölü / sarkan sınıf, paketlenmiş bir sağlayıcı-parmak izi DB'sine (can-i-take-over-xyz) karşı <strong>çevrimdışı</strong> eşleştirilir — nuclei'nin yapısal olarak ulaşamadığı bir sınıf.</li>
          <li><strong>TLS</strong> — <Mono>sslscan</Mono> → host başına geçti/kaldı <a href="#tls" className="text-primary hover:underline">karnesi</a>. Pasiftir, dolayısıyla WAF'ları tetiklemez.</li>
          <li><strong>Web CVE'leri</strong> — canlı web sunucularına karşı <Mono>nuclei</Mono> oto-tarama (şablonlar tespit edilen teknolojiyle sınırlanır).</li>
          <li><strong>Güvenlik başlıkları</strong> — httpx'in zaten yakaladığı yanıt başlıklarının deterministik, pasif analizi: OWASP en iyi-uygulama kataloğu ve yapılandırılmış bir CSP zafiyet taraması. Yeni istek yapılmaz.</li>
          <li><strong>Tedarik zinciri</strong> — Playwright/Chromium <a href="#profiling" className="text-primary hover:underline">tarayıcısı</a> (yalnızca-yapı yakalama).</li>
        </ul>
      </Section>

      <Section id="ai" title="Yapay zekâ analizi">
        <p>
          Yapay zekâ katmanının ayırt edici değeri <strong>uygulama-başına bağlam farkındalığıdır</strong>.
          Denetim dağılımından sonra çalışır — profilleyici en başta olur ki, onu tüketen iki analiz
          adımından önce tarayıcının render edilmiş yakalamasını okuyabilsin.
        </p>
        <Figure caption="Yapay zekâ aşaması. Profil önce üretilir ve her iki alt adımı da besler.">
          <AiFlow />
        </Figure>
        <ul className="ml-4 list-disc space-y-1.5">
          <li><strong>ai.profile</strong> — her uygulamanın ne olduğunu (giriş portalı, API, tanıtım sitesi…) ve sahip olması gereken kontrolleri çıkarır. Girdisi <a href="#profiling" className="text-primary hover:underline"><Mono>ai.profile.render</Mono></a> ile belirlenir.</li>
          <li><strong>ai.triage</strong> — host başına <em>tüm</em> deterministik bulguları (nuclei / TLS / js_lib / headers / takeover) gözden geçirir, muhtemel yanlış pozitifleri yumuşak bastırır ve kuralların kaçırdığı başlık sorunlarını ekler. Bkz. <a href="#suppression" className="text-primary hover:underline">Bastırma</a>.</li>
          <li><strong>ai.supply-chain</strong> — tarayıcının betikleri üzerinde risk değerlendirmesi; her biri <strong>Python tarafında</strong> 1./3. taraf olarak önceden etiketlenir (taraf kararını LLM asla vermez), profile göre ağırlıklandırılır.</li>
        </ul>
        <Callout>
          <strong>LLM bir tarayıcıyı asla geçitlemez.</strong> Her yapay zekâ yanıtı bir kez yeniden
          denenerek doğrulanır, ardından zarifçe gerilenir: başarısız bir profil bağlam-hafif
          istemlere düşer, gerilemiş bir çağrı <em>hata</em> olarak kaydedilir (çökme değil) ve bir
          yapay zekâ gerilemesi <strong>hiçbir şeyi bastırmaz</strong>. LLM erişilemezse veya
          kredisi biterse, yine de eksiksiz deterministik bulgu setini alırsınız — yalnızca yapay
          zekâ ek açıklamaları eksik olur.
        </Callout>
      </Section>

      <Section id="profiling" title="Profilleme ve sayfa yakalama">
        <p>
          Profilleyicinin girdisi <Mono>ai.profile.render</Mono> ile belirlenir (Ayarlar'da ya da
          Yeni-Tarama formunda tarama başına):
        </p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <Badge tone="good">auto</Badge> (varsayılan) — bir host için tedarik-zinciri tarayıcısı
            çalıştığında, profilleyici <strong>tarayıcıda render edilmiş</strong> metni ve sayfanın
            gerçekte yüklediklerinin küratörlü bir manifestini kullanır. Aksi halde hızlı, JavaScript
            öncesi HTTP getirisine düşer. Sırf profillemek için asla tarayıcı açılmaz.
          </li>
          <li>
            <Badge tone="muted">always</Badge> — tedarik zinciri kapalı olsa bile profillenen her
            hostu başsız bir tarayıcıda render eder (daha yavaş; host başına bir tarayıcı).
          </li>
          <li>
            <Badge tone="muted">never</Badge> — yalnızca JS öncesi HTTP sinyalleri.
          </li>
        </ul>
        <p>
          Bir sayfa render edildiğinde, tarayıcı <strong>yalnızca-yapı</strong> bir manifest yakalar
          — asla herhangi bir değer, çerez içeriği veya yanıt gövdesi değil. Bir tarama çıktısı
          paylaşılmak ve e-postalanmak için tasarlanmıştır; dolayısıyla hedefin sırlarını asla
          taşımamalıdır:
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Yakalanan</th>
                <th className="px-2 py-1.5 font-medium">İçeriği</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1.5 [&_td]:align-top">
              <tr className="border-b border-border/50"><td><Mono>resources</Mono></td><td>her yanıt: url / type / status / method (tekilleştirilmiş, ≤ 500)</td></tr>
              <tr className="border-b border-border/50"><td><Mono>scripts</Mono></td><td>betik-yanıt URL'leri (js_libs + tedarik zincirini besler)</td></tr>
              <tr className="border-b border-border/50"><td><Mono>cookies</Mono></td><td>ad + bayraklar (secure / httpOnly / sameSite / domain / path) — <strong>değer yok</strong></td></tr>
              <tr className="border-b border-border/50"><td><Mono>storage anahtarları</Mono></td><td>localStorage / sessionStorage <strong>yalnızca anahtar adları</strong></td></tr>
              <tr className="border-b border-border/50"><td><Mono>rendered_text</Mono></td><td><Mono>body.innerText</Mono>, boşluk-normalize, ≤ 2 KB</td></tr>
              <tr><td><Mono>screenshot</Mono></td><td>isteğe bağlı host-başına PNG (görünüm) — yalnızca panoda</td></tr>
            </tbody>
          </table>
        </div>
        <p>
          Bu küratörlü, yalnızca-adlardan oluşan yüzey ayrıca varlık başına saklanır (Varlıklar → bir
          satırın Detayları → <em>Yüzey / bağlantılar</em>) ki “bu host neyi çağırıyor?” sorusunu
          yanıtlayabilesiniz — hafif bir EASM görünümü. Ekran görüntüleri de aynı panelde gösterilir
          ve taşınabilir <Mono>report.html</Mono>'a <strong>asla</strong> gömülmez ya da LLM'e
          gönderilmez.
        </p>
      </Section>

      <Section id="throttle" title="Hız sınırlama kademeleri">
        <p>
          Tek bir nmap tarzı nezaket kademesi tüm araçlara aynı anda uygulanır; açıkça verilen her
          araç-özel değer onu geçersiz kılar. <strong>httpx thread sayısı</strong>, WAF'lı hedeflere
          karşı kaynak-engellemenin baş tetikleyicisidir — sertleştirilmiş bir hedef 0 canlı sunucu
          döndürüyorsa <Mono>gentle</Mono>'a inin (gerçek engel-aşma kolu budur; gizli başlıklar
          değil).
        </p>
        <div className="space-y-1.5">
          {THROTTLE_PROFILES.map((p) => (
            <div key={p} className="flex flex-col gap-0.5 rounded-lg border border-border p-3 sm:flex-row sm:items-baseline sm:gap-3">
              <Mono>{p}</Mono>
              <span className="text-xs text-muted-foreground">{THROTTLE_NOTES[p]}</span>
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">Kademe başına tam ayar değerleri:</p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse whitespace-nowrap text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Kademe</th>
                <th className="px-2 py-1.5 font-medium">httpx hız / thread</th>
                <th className="px-2 py-1.5 font-medium">nuclei hız</th>
                <th className="px-2 py-1.5 font-medium">takeovers hız</th>
                <th className="px-2 py-1.5 font-medium">dnsx hız</th>
                <th className="px-2 py-1.5 font-medium">tlsx eşz.</th>
                <th className="px-2 py-1.5 font-medium">sslscan zaman aşımı</th>
                <th className="px-2 py-1.5 font-medium" title="varsayılan / tls / playwright">eşz. (vars/tls/pw)</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1.5">
              {THROTTLE_DETAIL.map((r) => (
                <tr key={r.tier} className="border-b border-border/50">
                  <td><Mono>{r.tier}</Mono></td>
                  <td className="font-mono text-foreground">{r.httpx}</td>
                  <td className="font-mono">{r.nuclei}</td>
                  <td className="font-mono">{r.takeovers}</td>
                  <td className="font-mono">{r.dnsx}</td>
                  <td className="font-mono">{r.tlsx}</td>
                  <td className="font-mono">{r.tls}</td>
                  <td className="font-mono">{r.conc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-muted-foreground">
          <Mono>hız</Mono> = istek hızı (istek/sn). <Mono>eşz.</Mono> = paralel host sınırları (genel
          dağılım / TLS taramaları / tarayıcı bağlamları).
        </p>
      </Section>

      <Section id="identity" title="Gizli kimlik">
        <Callout tone="warn">
          <strong>YETKİLİ testler için, kendi varlıklarınızda.</strong> Tutarlı bir tarayıcı kimliği
          yalnızca naif UA / başlık WAF kurallarını aşar — <strong>TLS / JA3 parmak izlemeyi ya da
          IP-itibarını değil</strong>. Onlar için tarayıcı IP'sini izin listesine aldırın.
        </Callout>
        <p>
          <Mono>identity.preset</Mono>, tutarlı bir tarayıcı User-Agent + başlıklar + yerel ayar
          paketi sunar; bunlar <strong>httpx</strong>, <strong>nuclei</strong> ve{" "}
          <strong>Playwright tarayıcısına</strong> enjekte edilir. Varsayılan <Mono>chrome-win</Mono>
          'dur — <Mono>off</Mono> yapılmadıkça her tarama bir Chrome-on-Windows kimliği sunar.{" "}
          <Mono>user_agent</Mono> / <Mono>headers</Mono> / <Mono>locale</Mono> onu geçersiz kılar ya
          da genişletir (<Mono>X-Forwarded-For</Mono> gibi tuzaklar <Mono>headers</Mono>'a girer).
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-2 py-1.5 font-medium">Profil</th>
                <th className="px-2 py-1.5 font-medium">User-Agent</th>
                <th className="px-2 py-1.5 font-medium">Platform ipucu</th>
                <th className="px-2 py-1.5 font-medium">UA Client Hints</th>
              </tr>
            </thead>
            <tbody className="[&_td]:px-2 [&_td]:py-1.5 [&_td]:align-top">
              {IDENTITY_PRESETS.map((p) => (
                <tr key={p.name} className="border-b border-border/50">
                  <td>
                    <Mono>{p.name}</Mono>
                    {p.isDefault && <span className="ml-1.5 text-[10px] text-primary">varsayılan</span>}
                  </td>
                  <td className="text-muted-foreground">{p.ua}</td>
                  <td className="font-mono">{p.platform}</td>
                  <td className="text-muted-foreground">{p.hints}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          <strong>Neden yalnızca düşük-entropili client hints?</strong> Chrome profilleri, gerçek bir
          tarayıcının soğuk ilk istekte gönderdiği ipuçlarını gönderir — <Mono>Sec-CH-UA</Mono>,{" "}
          <Mono>Sec-CH-UA-Mobile</Mono>, <Mono>Sec-CH-UA-Platform</Mono>. Yüksek-entropili ipuçları
          (<Mono>-Arch</Mono>, <Mono>-Full-Version-List</Mono>, <Mono>-Platform-Version</Mono>…) ve
          Google'a özel <Mono>x-client-data</Mono> / <Mono>x-browser-*</Mono>{" "}
          <strong>bilinçli olarak atlanır</strong>: bir tarayıcı bunları yalnızca sunucu{" "}
          <Mono>Accept-CH</Mono> ile izin verdikten sonra gönderir; dolayısıyla istenmeden göndermek
          başlı başına bir bot işaretidir.
        </p>
        <p>
          <strong>Referrer rotasyonu.</strong> Bir tarayıcı profili, araç koşusu başına makul bir{" "}
          <Mono>Referer</Mono> döndürür (httpx / nuclei / tarayıcı her biri bağımsız bir tane alır) —
          10 girişlik harici arama / sosyal köken havuzundan. Her giriş harici bir köken olduğundan,
          tutarlı <Mono>Sec-Fetch-Site</Mono> <Mono>cross-site</Mono>'tır (başka yerden gelen bir
          tıklama — yazılan / yer-imli bir URL anlamına gelen <Mono>none</Mono> değil). Rotasyondan
          çıkmak için <Mono>headers.Referer</Mono> ile sabit bir değer iğneleyin.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {REFERER_POOL.map((r) => (
            <span key={r} className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">{r}</span>
          ))}
        </div>
      </Section>

      <Section id="tls" title="TLS karnesi">
        <p>
          <Mono>tls</Mono> yeteneği her canlı web sunucusuna karşı <strong>sslscan</strong> çalıştırır
          ve sonucu geçti/kaldı karnesine dönüştürür. Pasiftir — saldırı-imzası probu yoktur —
          dolayısıyla daha gürültülü bir tarayıcıyı engelleten WAF'ları tetiklemez. Kontroller:
        </p>
        <ul className="ml-4 list-disc space-y-1">
          <li>Güvensiz protokoller kapalı (SSLv2 / SSLv3 / TLS 1.0 / TLS 1.1)</li>
          <li>Zayıf şifreleme yok (RC4 / 3DES / DES / EXPORT / NULL / MD5 / anonim / &lt; 112-bit)</li>
          <li>Sertifika geçerli ve son kullanmaya &gt; 30 gün</li>
          <li>Anahtar gücü (RSA ≥ 2048 / EC ≥ 256) ve imza algoritması SHA-1 / MD5 değil</li>
          <li>Güvenli yeniden anlaşma (renegotiation) destekli</li>
        </ul>
        <p>
          Ayrıca keşif aşaması tlsx ile pasif bir <strong>sertifika dosyası</strong> toplar (veren,
          son kullanma, seri, SHA-256, kendinden imzalı / joker) — yalnızca envanter, Certs sekmesinde
          gösterilir. HSTS, burada değil, <Mono>headers</Mono> yeteneği altındadır.
        </p>
      </Section>

      <Section id="suppression" title="Bastırma">
        <p>Bir bulgunun gizlenmesinin iki ayrı yolu vardır. Hiçbiri onu asla silmez — her bulgu{" "}
          <Mono>findings.json</Mono>'da korunur; bastırma yalnızca onu rapor görünümünden ve önem
          sayımlarından çıkarır.</p>
        <ul className="ml-4 list-disc space-y-1.5">
          <li>
            <strong>Yapay zekâ yanlış pozitifi</strong> — <Mono>ai.triage</Mono> adımı host başına
            deterministik bulguları yargılar ve muhtemel yanlış pozitifleri yumuşak bastırır. Her
            taramada yeniden yargılanır; bulgular tablosunun katlanabilir bir bölümünde satır içinde
            gösterilir. Güven / önem tavanlarıyla geçitlenir (varsayılan: orta güven, orta önem
            tavanı), böylece yüksek önemli bulgular asla otomatik gizlenmez.
          </li>
          <li>
            <strong>Manuel</strong> — bir bulgudaki göz-kapalı düğmesiyle oluşturduğunuz koşular-arası
            bir kural. <Mono>source · host · key</Mono> ile eşleştirilir; <Mono>*</Mono> hostu “her
            yerde” demektir. Bastırmalar sayfasından yönetilir.
          </li>
        </ul>
        <p>
          Bulgular tablosunda, çok-hostlu bir sorunu satırdan bastırmak onu <em>her yerde</em>{" "}
          bastırır; satırı genişletip host-başına düğmeyle <em>yalnızca bir hostta</em> bastırın.
        </p>
      </Section>

      <Section id="first-scan" title="İlk taramanız">
        <ol className="ml-4 list-decimal space-y-1.5">
          <li>
            <strong>Ayarlar → Tarama yapılandırması</strong>'nda LLM uç noktasını + API anahtarını
            ayarlayın. (MMDB isteğe bağlıdır.) Bir tarama yalnızca geçerli bir LLM yapılandırmasına
            göre geçitlenir.
          </li>
          <li>
            Yeni-Tarama sayfasında anlık kökler girin ya da Varlıklar sayfasında varlık içe aktarın
            (CSV <Mono>domain,group</Mono>) ve bir grubu tarayın.
          </li>
          <li><strong>Yeni Tarama</strong>'yı açın, bir hazır ayar seçin, bir hız kademesi seçin ve başlatın.</li>
          <li>
            Tarama detay sayfasında <strong>Bulgular</strong> sekmesi her sorunu host'a göre katlar —
            tam olarak hangi hostların etkilendiğini görmek ve doğrudan o varlığa atlamak için bir
            satırı genişletin.
          </li>
          <li>Triyaj ederken gürültüyü bastırın; sayımlar bir sonraki taramada güncellenir.</li>
        </ol>
      </Section>

      <Section id="scheduling" title="Zamanlama">
        <p>
          Zamanlamalar normal bir taramayı dostça bir kadansla çalıştırır (saatlik / günlük /
          haftalık, isteğe bağlı gün-saati ve hafta günü ile, UTC olarak). Bir zamanlama, halihazırda
          bir tarama çalışıyorsa kendini atlar ve sunucu kapalıyken gecikmişse açılışta bir kez
          çalışır. Hedefler manuel taramayla aynı seçiciyi kullanır (kökler / grup / belirli varlıklar
          / tüm varlıklar).
        </p>
      </Section>

      {/* Yetenek referansı en sonda — anlatısal bir adım değil, bir arama tablosu. */}
      <Section id="capabilities" title="Yetenek referansı">
        <p>
          Bir tarama yetenek <em>token</em>'larından oluşur. Varsayılan olarak her yetenek çalışır;
          bir alt kümeyi çalıştırmak için <Mono>only</Mono>, belirli olanları düşürmek için{" "}
          <Mono>skip</Mono> kullanın. Keşif omurgası her zaman bir ön koşul olarak çalışır. Dört
          yetenek daha ince kontrol için noktalı alt-token'lara bölünür (ör.{" "}
          <Mono>recon.subfinder</Mono>, <Mono>nuclei.critical</Mono>). Token adları ve açıklamaları
          tanımlandıkları gibi (İngilizce) gösterilir:
        </p>
        <div className="space-y-2">
          {CAPABILITY_TOKENS.map((t) => (
            <div key={t.token} className="rounded-lg border border-border p-3">
              <div className="flex items-baseline gap-2">
                <Mono>{t.token}</Mono>
                <span className="text-sm font-medium">{t.label}</span>
              </div>
              <p className="mt-0.5 text-xs text-muted-foreground">{t.description}</p>
              {t.children && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {t.children.map((c) => (
                    <span key={c.token} title={c.description}
                      className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                      {c.token}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          Yeni-Tarama sayfası, bu token'lara eşlenen yerleşik hazır ayarlar (Tam denetim, Hızlı,
          Yalnızca keşif, TLS + başlıklar) sunar — sonra ince ayar yapabileceğiniz hızlı bir başlangıç.
        </p>
      </Section>
    </div>
  );
}

/* ── diyagram kompozisyonları (Türkçe etiketler) — primitifler @/components/docs/ui içinde ── */

function PipelineDiagram() {
  const stages: { t: string; s: string; accent?: boolean }[] = [
    { t: "Keşif", s: "keşif + triyaj" },
    { t: "Denetim", s: "paralel dağılım" },
    { t: "Yapay zekâ", s: "profil · triyaj · özet" },
    { t: "Birleştir", s: "bulguları birleştir" },
    { t: "report + executive", s: "tek dosya", accent: true },
  ];
  return (
    <div className="overflow-x-auto pb-1">
      <div className="flex min-w-max items-stretch gap-2">
        {stages.map((st, i) => (
          <Fragment key={st.t}>
            <FlowNode title={st.t} sub={st.s} tone={st.accent ? "accent" : "default"} />
            {i < stages.length - 1 && <span className="flex items-center"><Arrow /></span>}
          </Fragment>
        ))}
      </div>
    </div>
  );
}

function ReconFlow() {
  return (
    <div className="flex flex-col items-center gap-1.5">
      <FlowNode title="subfinder + kökler" sub="aday adlar" />
      <Arrow dir="down" />

      {/* DNS → TLS yeniden keşif döngüsü, geri-dönüş teliyle bir çevrim olarak çizilir */}
      <div className="relative w-full max-w-sm rounded-lg border border-dashed border-primary/50 px-3 pb-3 pt-4">
        <span className="absolute -top-2 left-1/2 -translate-x-1/2 whitespace-nowrap bg-card px-1.5 text-[10px] font-medium text-primary">
          🔁 DNS → TLS yeniden keşif döngüsü · ≤ 3×
        </span>
        <div className="flex items-stretch gap-3">
          {/* geri-dönüş teli: tlsx (alt) → dnsx (üst) */}
          <div className="relative flex w-5 flex-col items-center">
            <span className="text-sm leading-none text-primary">▲</span>
            <div className="w-px flex-1 bg-primary/50" />
            <span className="absolute top-1/2 -translate-y-1/2 text-[9px] uppercase tracking-wide text-primary [writing-mode:vertical-rl] rotate-180">
              yeni SAN
            </span>
          </div>
          {/* ileri yol */}
          <div className="flex flex-1 flex-col items-center gap-1.5">
            <FlowNode title="dnsx" sub="A + CNAME çöz" className="w-full" />
            <Arrow dir="down" />
            <FlowNode title="triage" sub="canlılık — canlı / ölü" tone="accent" className="w-full" />
            <Arrow dir="down" />
            <FlowNode title="tlsx :443" sub="SAN toplama + sertifika dosyası" className="w-full" />
          </div>
        </div>
      </div>

      <Arrow dir="down" />
      <FlowNode title="httpx" sub="canlı web sunucuları → PageSignals" />
    </div>
  );
}

function AuditFanout() {
  const nodes = [
    { t: "takeovers", s: "nuclei + çevrimdışı DB" },
    { t: "tls", s: "sslscan karnesi" },
    { t: "nuclei", s: "web CVE'leri" },
    { t: "headers", s: "OWASP + CSP" },
    { t: "supply-chain", s: "tarayıcı" },
  ];
  return (
    <div className="flex flex-col items-center gap-1.5">
      <FlowNode title="canlı hostlar" sub="keşiften" tone="accent" />
      <Arrow dir="down" />
      <div className="grid w-full grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {nodes.map((n) => <FlowNode key={n.t} title={n.t} sub={n.s} className="min-w-0" />)}
      </div>
    </div>
  );
}

function AiFlow() {
  return (
    <div className="flex flex-col items-center gap-1.5">
      <FlowNode title="ai.profile" sub="bu uygulama nedir? · beklenen kontroller" tone="accent" />
      <Arrow dir="down" />
      <div className="grid w-full grid-cols-1 gap-2 sm:grid-cols-2">
        <FlowNode title="ai.triage" sub="yanlış pozitifleri bastır + başlık boşlukları" className="min-w-0" />
        <FlowNode title="ai.supply-chain" sub="betik riski, taraf-ağırlıklı" className="min-w-0" />
      </div>
    </div>
  );
}
