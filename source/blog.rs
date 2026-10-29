//! Static blog: articles are full HTML files under `web/blog/`.
//!
//! Adding an article later needs no rebuild or restart: drop a file named
//! `<slug>.html` into `web/blog/` (slug: `[a-z0-9-]{1,100}`), give it the
//! required SEO meta (see `extract_meta_content`), and add its URL to
//! `web/sitemap.xml`. The list page scans the directory on each request,
//! so a new file shows up automatically.
//!
//! Security: the slug is validated to a strict charset BEFORE any path is
//! built, and the path is never assembled from raw user input, so no
//! traversal (`..`, `/`, percent-encoded separators) can escape `web/blog/`.

use axum::{
    extract::Path,
    http::{header, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
};

use crate::api::not_found_page;

/// Normalize a raw URL slug: strip one trailing `.html`, then require
/// `[a-z0-9-]{1,100}`. Anything else (uppercase, dots, slashes, encoded
/// separators, empty, too long) is rejected.
pub fn normalize_blog_slug(raw: &str) -> Option<String> {
    let stripped = raw.strip_suffix(".html").unwrap_or(raw);
    if stripped.is_empty() || stripped.len() > 100 {
        return None;
    }
    if !stripped
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    Some(stripped.to_string())
}

/// Canonical redirect for the bare list path: `/blog` → `/blog/`.
/// Anything else (including `/blog/` itself) is served, not redirected.
pub fn list_redirect_target(path: &str) -> Option<&'static str> {
    if path == "/blog" {
        Some("/blog/")
    } else {
        None
    }
}

/// Canonical redirect for a bare article slug: `/blog/<slug>` →
/// `/blog/<slug>.html`. None when the slug already carries the suffix
/// (serve it) or is invalid (404 it — never redirect garbage).
pub fn article_redirect_target(raw: &str) -> Option<String> {
    if raw.ends_with(".html") {
        return None;
    }
    normalize_blog_slug(raw).map(|slug| format!("/blog/{slug}.html"))
}

fn permanent_redirect(location: &str) -> Response {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

fn blog_path(slug: &str) -> std::path::PathBuf {
    // The slug charset is already validated by the caller; this never
    // touches raw user input.
    let mut path = std::path::PathBuf::from("web");
    path.push("blog");
    path.push(format!("{slug}.html"));
    path
}

/// One list entry, derived from an article file's own SEO meta.
struct BlogEntry {
    slug: String,
    title: String,
    description: String,
    /// ISO date (`YYYY-MM-DD`) from `article:published_time`.
    date: String,
    /// Indonesian display date, e.g. `27 Oktober 2026`.
    date_display: String,
    /// Cover image URL from the article's `og:image` (absolute when the
    /// article declares one); None when the article has no cover.
    image: Option<String>,
    /// Cover alt text from `og:image:alt`; falls back to the title.
    image_alt: String,
    /// Estimated reading time in minutes, from the article body's word
    /// count; None when the body cannot be found (the card then omits
    /// the reading time rather than showing a wrong number).
    reading_minutes: Option<u64>,
}

/// Newest first; ties break on slug ascending so the order is stable.
fn sort_blog_entries(entries: &mut Vec<BlogEntry>) {
    entries.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.slug.cmp(&b.slug)));
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Undo the few entities our own article files may contain in meta values,
/// so the list page escapes them exactly once.
fn unescape_meta_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Extract `<title>…</title>` text, trimmed. None when absent or empty.
fn extract_title(html: &str) -> Option<String> {
    let start = html.find("<title>")? + "<title>".len();
    let end = html[start..].find("</title>")? + start;
    let title = html[start..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(unescape_meta_entities(title))
    }
}

/// Extract the `content` of a `<meta>` tag carrying `attr="value"`
/// (attribute order inside the tag does not matter). Double quotes only,
/// matching the convention used by the article files.
fn extract_meta_content(html: &str, attr: &str, value: &str) -> Option<String> {
    let needle = format!("{attr}=\"{value}\"");
    let mut rest = html;
    while let Some(tag_start) = rest.find("<meta") {
        let tag_rest = &rest[tag_start..];
        let tag_end = tag_rest.find('>')?;
        let tag = &tag_rest[..tag_end];
        if tag.contains(&needle) {
            if let Some(content_start) = tag.find("content=\"") {
                let value_start = content_start + "content=\"".len();
                let value_end = tag[value_start..].find('"')? + value_start;
                let content = tag[value_start..value_end].trim();
                if !content.is_empty() {
                    return Some(unescape_meta_entities(content));
                }
            }
        }
        rest = &tag_rest[tag_end + 1..];
    }
    None
}

/// `YYYY-MM-DD` shape check (lexicographic sort relies on it).
fn valid_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes.iter().enumerate().all(|(i, b)| {
            i == 4 || i == 7 || b.is_ascii_digit()
        })
}

fn format_date_id(date: &str) -> String {
    const MONTHS: [&str; 12] = [
        "Januari",
        "Februari",
        "Maret",
        "April",
        "Mei",
        "Juni",
        "Juli",
        "Agustus",
        "September",
        "Oktober",
        "November",
        "Desember",
    ];
    let year = &date[0..4];
    let month: usize = date[5..7].parse().unwrap_or(0);
    let day = date[8..10].trim_start_matches('0');
    if month < 1 || month > 12 || day.is_empty() {
        return date.to_string();
    }
    format!("{} {} {}", day, MONTHS[month - 1], year)
}

/// Strip markup to plain text: tags are removed and `<script>`/`<style>`
/// block contents are skipped entirely (they are code, not prose).
/// Tag names are matched case-insensitively; only `<script`/`<style>` with
/// a name boundary count as block openers.
fn strip_markup_text(html: &str) -> String {
    let lower = html.to_lowercase();
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;
    while i < bytes.len() {
        let rest = &lower[i..];
        let is_block = |tag: &str| -> bool {
            rest.starts_with(tag)
                && rest[tag.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| c.is_whitespace() || c == '>')
        };
        if is_block("<script") || is_block("<style") {
            let close = if is_block("<script") {
                "</script>"
            } else {
                "</style>"
            };
            match rest.find(close) {
                Some(off) => i += off + close.len(),
                None => break,
            }
        } else if bytes[i] == b'<' {
            match html[i..].find('>') {
                Some(off) => i += off + 1,
                None => break,
            }
        } else {
            let end = html[i..].find('<').map(|o| i + o).unwrap_or(bytes.len());
            out.push_str(&html[i..end]);
            out.push(' ');
            i = end;
        }
    }
    out
}

/// Estimated reading time at 200 words/minute, rounded up, minimum 1.
/// Counts only the `<article>` body (site header/footer boilerplate and
/// head scripts are not prose). None when there is no article body or
/// it contains no words — the caller omits the reading time then.
fn reading_minutes_from_html(html: &str) -> Option<u64> {
    let start = html.find("<article")?;
    let content_start = html[start..].find('>')? + start + 1;
    let content_end = html[content_start..].find("</article>")? + content_start;
    let text = strip_markup_text(&html[content_start..content_end]);
    let words = text.split_whitespace().count();
    if words == 0 {
        return None;
    }
    Some(((words + 199) / 200) as u64)
}

/// Card image source: site-absolute `og:image` URLs become same-origin
/// paths; anything else is used as-is.
fn card_image_src(og_image: &str) -> &str {
    og_image
        .strip_prefix("https://www.rajacek.com")
        .unwrap_or(og_image)
}

/// JSON-escape for embedding a string in a JSON-LD script block.
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            _ => out.push(ch),
        }
    }
    out
}

/// JSON-LD for the list page: a Blog with its posts plus a BreadcrumbList
/// (Beranda → Blog). Pure (unit-testable), so the emitted script is
/// always valid JSON.
fn blog_list_json_ld(entries: &[BlogEntry]) -> String {
    let mut posts = String::new();
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            posts.push(',');
        }
        posts.push_str(&format!(
            "{{\"@type\":\"BlogPosting\",\"headline\":\"{}\",\"url\":\"https://www.rajacek.com/blog/{}.html\",\"datePublished\":\"{}\"}}",
            json_escape(&entry.title),
            entry.slug,
            entry.date
        ));
    }
    format!(
        "<script type=\"application/ld+json\">{{\"@context\":\"https://schema.org\",\"@graph\":[{{\"@type\":\"Blog\",\"name\":\"Blog Rajacek\",\"url\":\"https://www.rajacek.com/blog/\",\"description\":\"Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya.\",\"inLanguage\":\"id-ID\",\"blogPost\":[{}]}},{{\"@type\":\"BreadcrumbList\",\"itemListElement\":[{{\"@type\":\"ListItem\",\"position\":1,\"name\":\"Beranda\",\"item\":\"https://www.rajacek.com/\"}},{{\"@type\":\"ListItem\",\"position\":2,\"name\":\"Blog\",\"item\":\"https://www.rajacek.com/blog/\"}}]}}]}}</script>",
        posts
    )
}

/// One premium card for a list entry. `featured` renders the newest
/// article large (eager image); the rest render as standard grid cards
/// (lazy images). Images keep a uniform 1200/630 aspect ratio with
/// object-fit cover so covers crop instead of distorting.
fn render_blog_card(entry: &BlogEntry, featured: bool) -> String {
    let img = match &entry.image {
        Some(src) => format!(
            "<img class=\"blog-card-img\" src=\"{}\" width=\"1200\" height=\"630\" loading=\"{}\" decoding=\"async\" alt=\"{}\" />",
            escape_html(card_image_src(src)),
            if featured { "eager" } else { "lazy" },
            escape_html(&entry.image_alt),
        ),
        None => String::new(),
    };
    let minutes = match entry.reading_minutes {
        Some(m) => format!(" · {} menit baca", m),
        None => String::new(),
    };
    let featured_class = if featured {
        " blog-card--featured"
    } else {
        ""
    };
    format!(
        r##"<article class="blog-card{featured_class}">{img}<div class="blog-card-body"><p class="blog-meta">{date}{minutes}</p><h2><a href="/blog/{slug}.html">{title}</a></h2><p class="blog-card-desc">{description}</p><p><a class="blog-readmore" href="/blog/{slug}.html">Baca selengkapnya <span aria-hidden="true">→</span></a></p></div></article>"##,
        featured_class = featured_class,
        img = img,
        date = escape_html(&entry.date_display),
        minutes = minutes,
        slug = entry.slug,
        title = escape_html(&entry.title),
        description = escape_html(&entry.description),
    )
}

async fn read_blog_entries() -> Vec<BlogEntry> {
    let mut entries = Vec::new();
    let mut dir = match tokio::fs::read_dir("web/blog").await {
        Ok(dir) => dir,
        Err(_) => return entries,
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".html") else {
            continue;
        };
        // Only files whose stem is itself a valid slug appear in the list.
        if normalize_blog_slug(stem).is_none() {
            continue;
        }
        let Ok(text) = tokio::fs::read_to_string(entry.path()).await else {
            continue;
        };
        // Required SEO meta: without it the file stays directly reachable
        // by URL but does not appear in the list.
        let Some(title) = extract_title(&text) else {
            continue;
        };
        let Some(description) = extract_meta_content(&text, "name", "description") else {
            continue;
        };
        let Some(date) = extract_meta_content(&text, "property", "article:published_time") else {
            continue;
        };
        if !valid_date(&date) {
            continue;
        }
        let image = extract_meta_content(&text, "property", "og:image");
        let image_alt = extract_meta_content(&text, "property", "og:image:alt")
            .unwrap_or_else(|| title.clone());
        entries.push(BlogEntry {
            slug: stem.to_string(),
            title,
            description,
            date_display: format_date_id(&date),
            date,
            image,
            image_alt,
            reading_minutes: reading_minutes_from_html(&text),
        });
    }
    sort_blog_entries(&mut entries);
    entries
}

/// `GET /blog` (301 → `/blog/`) and `GET /blog/`: article list, newest first.
pub async fn blog_list(uri: Uri) -> Response {
    if let Some(target) = list_redirect_target(uri.path()) {
        return permanent_redirect(target);
    }
    let entries = read_blog_entries().await;
    let mut items = String::new();
    if entries.is_empty() {
        items.push_str("<p class=\"blog-empty\">Belum ada artikel.</p>");
    } else {
        // Newest first (entries are already sorted): the first entry is
        // the wide featured card, the rest form the standard grid.
        let (featured, rest) = entries.split_first().unwrap();
        items.push_str(&render_blog_card(featured, true));
        if !rest.is_empty() {
            items.push_str("<div class=\"blog-grid\">");
            for entry in rest {
                items.push_str(&render_blog_card(entry, false));
            }
            items.push_str("</div>");
        }
    }
    let html = format!(
        r##"<!doctype html>
<html lang="id">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Blog Rajacek — Validasi Rekening, E-Wallet, WhatsApp &amp; PLN</title>
    <meta name="description" content="Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya." />
    <meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1" />
    <meta name="author" content="PT DATA BRIDGE NUSANTARA" />
    <link rel="canonical" href="https://www.rajacek.com/blog/" />
    <link rel="icon" href="/favicon.png?v=20261028-1" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Rajacek" />
    <meta property="og:locale" content="id_ID" />
    <meta property="og:title" content="Blog Rajacek — Validasi Rekening, E-Wallet, WhatsApp &amp; PLN" />
    <meta property="og:description" content="Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya." />
    <meta property="og:url" content="https://www.rajacek.com/blog/" />
    <meta property="og:image" content="https://www.rajacek.com/og-cover.png?v=20261028-1" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="Blog Rajacek — Validasi Rekening, E-Wallet, WhatsApp &amp; PLN" />
    <meta name="twitter:description" content="Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya." />
    <meta name="twitter:image" content="https://www.rajacek.com/og-cover.png?v=20261028-1" />
    {json_ld}
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/landing.css?v=20261030-1" />
    <style>
      .blog-list {{ width:min(1180px,calc(100% - 40px)); margin:auto; padding:48px 0 72px; }}
      .blog-list h1 {{ color:var(--navy); font-size:clamp(31px,4vw,46px); line-height:1.12; letter-spacing:-2px; margin-bottom:12px; }}
      .blog-list .lede {{ color:var(--muted); font-size:16px; margin-bottom:36px; }}
      .blog-card {{ min-width:0; overflow:hidden; border:1px solid var(--line); border-radius:var(--radius); background:var(--white); transition:transform .2s,box-shadow .2s; }}
      .blog-card:hover {{ transform:translateY(-4px); box-shadow:0 22px 42px #152d4d14; }}
      .blog-card-img {{ display:block; width:100%; height:auto; aspect-ratio:1200 / 630; object-fit:cover; }}
      .blog-card-body {{ padding:22px 24px 24px; }}
      .blog-meta {{ color:var(--muted); font-size:13px; margin:0 0 8px; }}
      .blog-card h2 {{ font-size:21px; letter-spacing:-.5px; margin:0 0 8px; }}
      .blog-card h2 a:hover {{ color:var(--blue); }}
      .blog-card h2 a:focus-visible, .blog-readmore:focus-visible {{ outline:2px solid var(--blue); outline-offset:2px; }}
      .blog-card-desc {{ color:var(--muted); font-size:15px; margin:0 0 14px; }}
      .blog-readmore {{ color:var(--blue); font-size:14px; font-weight:800; }}
      .blog-card--featured {{ margin-bottom:28px; }}
      .blog-empty {{ color:var(--muted); }}
      @media (min-width:860px) {{
        .blog-card--featured {{ display:grid; grid-template-columns:1.05fr .95fr; align-items:stretch; }}
        .blog-card--featured .blog-card-img {{ height:100%; }}
        .blog-card--featured .blog-card-body {{ align-self:center; padding:28px 30px; }}
        .blog-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:24px; }}
      }}
      @media (max-width:480px) {{ .blog-list {{ width:calc(100% - 28px); padding:36px 0 56px; }} .blog-card-body {{ padding:18px; }} }}
    
      .blog-hero {{ background:linear-gradient(180deg,#4D52B4,#4E9CE8,#70D6C5,#CAE5BC,#E1EDD4); border-radius:28px; padding:36px 32px; margin-bottom:28px; }}
      .blog-hero h1 {{ color:#fff; margin:0; }}
</style>
  </head>
  <body>
    <a class="skip-link" href="#content">Lewati ke konten utama</a>
    <header class="site-header">
      <a class="brand" href="/" aria-label="Rajacek, beranda"><img class="brand-mark-img" src="/logo-mark.png?v=20261028-1" alt="" aria-hidden="true"><span>aja<span>cek</span></span></a>
      <nav aria-label="Navigasi utama"><a href="/">Beranda</a><a href="/docs">Dokumentasi</a><a href="/blog/">Blog</a></nav>
      <a class="nav-cta" href="/member">Masuk dashboard <span aria-hidden="true">→</span></a>
    </header>
    <main id="content">
      <div class="blog-list">
        <p class="eyebrow">Blog</p>
        <div class="blog-hero">
          <h1>Blog Rajacek</h1>
        </div>
        <p class="lede">Artikel tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya.</p>
        {items}
      </div>
    </main>
    <footer><a class="brand" href="/" aria-label="Rajacek, beranda"><img class="brand-mark-img" src="/logo-mark.png?v=20261028-1" alt="" aria-hidden="true"><span>aja<span>cek</span></span></a><p>© 2026 Rajacek · PT DATA BRIDGE NUSANTARA — Infrastruktur validasi untuk Indonesia.<br><span class="foot-contact">Hubungi kami: <a href="mailto:apivalidasi@gmail.com">apivalidasi@gmail.com</a> · <a href="https://t.me/xyz_yaz" target="_blank" rel="noopener">Telegram @xyz_yaz</a></span></p></footer>
  </body>
</html>"##,
        items = items,
        json_ld = blog_list_json_ld(&entries),
    );
    Html(html).into_response()
}

/// `GET /blog/:slug`: bare slugs 301 → `/blog/<slug>.html`; suffixed
/// slugs serve the article file as-is. Unknown or invalid slugs get the
/// branded 404 page (never a file outside `web/blog/`).
pub async fn blog_article(Path(raw): Path<String>) -> Response {
    if let Some(target) = article_redirect_target(&raw) {
        return permanent_redirect(&target);
    }
    let Some(slug) = normalize_blog_slug(&raw) else {
        return not_found_page();
    };
    let path = blog_path(&slug);
    // Defense in depth: the constructed path must stay under web/blog.
    if !path.starts_with("web/blog") {
        return not_found_page();
    }
    match tokio::fs::read_to_string(&path).await {
        Ok(text) => Html(text).into_response(),
        Err(_) => not_found_page(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_validation_cases() {
        assert_eq!(normalize_blog_slug("validasi-pln"), Some("validasi-pln".to_string()));
        assert_eq!(
            normalize_blog_slug("validasi-pln.html"),
            Some("validasi-pln".to_string())
        );
        assert_eq!(normalize_blog_slug("a"), Some("a".to_string()));
        assert_eq!(normalize_blog_slug("a-1-b-2"), Some("a-1-b-2".to_string()));
        // Rejected: empty, uppercase, dots, slashes, traversal, encoded
        // separators, underscores, suffix edge cases, overlong.
        assert_eq!(normalize_blog_slug(""), None);
        assert_eq!(normalize_blog_slug(".html"), None);
        assert_eq!(normalize_blog_slug("Validasi-pln"), None);
        assert_eq!(normalize_blog_slug("validasi.pln"), None);
        assert_eq!(normalize_blog_slug(".."), None);
        assert_eq!(normalize_blog_slug("../etc"), None);
        assert_eq!(normalize_blog_slug("a/b"), None);
        assert_eq!(normalize_blog_slug("a%2e%2e"), None);
        assert_eq!(normalize_blog_slug("a%2f"), None);
        assert_eq!(normalize_blog_slug("validasi_pln"), None);
        assert_eq!(normalize_blog_slug("validasi-pln.HTML"), None);
        assert_eq!(normalize_blog_slug("validasi-pln.html.html"), None);
        assert_eq!(normalize_blog_slug(&"a".repeat(101)), None);
        assert_eq!(normalize_blog_slug(&"a".repeat(100)), Some("a".repeat(100)));
    }

    #[test]
    fn meta_extraction_handles_attribute_order() {
        let html = r#"<html><head><title>Judul &amp; Tes</title>
            <meta content="Deskripsi artikel." name="description" />
            <meta content="2026-10-27" property="article:published_time" />
            </head></html>"#;
        assert_eq!(extract_title(html).as_deref(), Some("Judul & Tes"));
        assert_eq!(
            extract_meta_content(html, "name", "description").as_deref(),
            Some("Deskripsi artikel.")
        );
        assert_eq!(
            extract_meta_content(html, "property", "article:published_time").as_deref(),
            Some("2026-10-27")
        );
        assert_eq!(extract_meta_content(html, "name", "keywords"), None);
        assert_eq!(extract_title("<html></html>"), None);
    }

    #[test]
    fn date_validation_and_format() {
        assert!(valid_date("2026-10-27"));
        assert!(!valid_date("2026-1-27"));
        assert!(!valid_date("27-10-2026"));
        assert!(!valid_date("2026/10/27"));
        assert_eq!(format_date_id("2026-10-27"), "27 Oktober 2026");
        assert_eq!(format_date_id("2026-01-05"), "5 Januari 2026");
    }

    #[test]
    fn list_order_newest_first_then_slug() {
        let mut entries = vec![
            BlogEntry {
                slug: "validasi-pln".to_string(),
                title: "PLN".to_string(),
                description: "d".to_string(),
                date: "2026-10-27".to_string(),
                date_display: "27 Oktober 2026".to_string(),
                image: None,
                image_alt: "PLN".to_string(),
                reading_minutes: None,
            },
            BlogEntry {
                slug: "validasi-nomor-rekening".to_string(),
                title: "Rekening".to_string(),
                description: "d".to_string(),
                date: "2026-10-27".to_string(),
                date_display: "27 Oktober 2026".to_string(),
                image: None,
                image_alt: "Rekening".to_string(),
                reading_minutes: None,
            },
            BlogEntry {
                slug: "lama".to_string(),
                title: "Lama".to_string(),
                description: "d".to_string(),
                date: "2026-10-20".to_string(),
                date_display: "20 Oktober 2026".to_string(),
                image: None,
                image_alt: "Lama".to_string(),
                reading_minutes: None,
            },
        ];
        sort_blog_entries(&mut entries);
        let slugs: Vec<&str> = entries.iter().map(|e| e.slug.as_str()).collect();
        assert_eq!(slugs, vec!["validasi-nomor-rekening", "validasi-pln", "lama"]);
    }

    #[test]
    fn html_escape_covers_markup_breakout() {
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn canonical_redirect_targets() {
        assert_eq!(list_redirect_target("/blog"), Some("/blog/"));
        assert_eq!(list_redirect_target("/blog/"), None);
        assert_eq!(list_redirect_target("/"), None);
        assert_eq!(
            article_redirect_target("validasi-pln").as_deref(),
            Some("/blog/validasi-pln.html")
        );
        assert_eq!(article_redirect_target("validasi-pln.html"), None);
        assert_eq!(article_redirect_target("Validasi-pln"), None);
        assert_eq!(article_redirect_target("a/b"), None);
        assert_eq!(article_redirect_target(".."), None);
        assert_eq!(article_redirect_target(""), None);
    }

    #[test]
    fn blog_list_json_ld_parses() {
        let entries = vec![BlogEntry {
            slug: "validasi-pln".to_string(),
            title: "Validasi PLN Kini Tersedia di Rajacek".to_string(),
            description: "d".to_string(),
            date: "2026-10-27".to_string(),
            date_display: "27 Oktober 2026".to_string(),
            image: None,
            image_alt: "PLN".to_string(),
            reading_minutes: None,
        }];
        let script = blog_list_json_ld(&entries);
        let json = script
            .trim_start_matches("<script type=\"application/ld+json\">")
            .trim_end_matches("</script>");
        let value: serde_json::Value =
            serde_json::from_str(json).expect("valid JSON-LD");
        let graph = value["@graph"].as_array().expect("@graph array");
        let blog = graph
            .iter()
            .find(|v| v["@type"] == "Blog")
            .expect("Blog node");
        assert_eq!(
            blog["blogPost"][0]["url"],
            "https://www.rajacek.com/blog/validasi-pln.html"
        );
        let crumbs = graph
            .iter()
            .find(|v| v["@type"] == "BreadcrumbList")
            .expect("BreadcrumbList node");
        assert_eq!(crumbs["itemListElement"][1]["name"], "Blog");
    }

    #[test]
    fn reading_minutes_counts_article_body_only() {
        // 200 words exactly → 1 minute; header/footer/script prose excluded.
        let mut body = String::from("<html><head><script>var a = \"one two three\";</script></head><body><header>Navi gasi</header><article><p>");
        body.push_str(&"kata ".repeat(200));
        body.push_str("</p></article><footer>Kaki halaman</footer></body></html>");
        assert_eq!(reading_minutes_from_html(&body), Some(1));
        let mut body2 = String::from("<article><p>");
        body2.push_str(&"kata ".repeat(201));
        body2.push_str("</p></article>");
        assert_eq!(reading_minutes_from_html(&body2), Some(2));
        // No article body, or an empty one: omit rather than guess.
        assert_eq!(reading_minutes_from_html("<html><p>teks</p></html>"), None);
        assert_eq!(
            reading_minutes_from_html("<article></article>"),
            None
        );
        // Script/style blocks inside the article do not count as prose.
        let scripted = "<article><script>alpha beta gamma</script><p>satu dua</p><style>.x{color:red}</style></article>";
        assert_eq!(reading_minutes_from_html(scripted), Some(1));
    }

    #[test]
    fn card_image_src_keeps_site_paths_relative() {
        assert_eq!(
            card_image_src("https://www.rajacek.com/blog/images/x.jpg"),
            "/blog/images/x.jpg"
        );
        assert_eq!(
            card_image_src("https://example.com/x.jpg"),
            "https://example.com/x.jpg"
        );
    }

    #[test]
    fn json_escape_covers_quotes_and_controls() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }
}
