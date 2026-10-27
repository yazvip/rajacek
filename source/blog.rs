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
        entries.push(BlogEntry {
            slug: stem.to_string(),
            title,
            description,
            date_display: format_date_id(&date),
            date,
        });
    }
    sort_blog_entries(&mut entries);
    entries
}

/// `GET /blog` and `GET /blog/`: article list, newest first.
pub async fn blog_list() -> Response {
    let entries = read_blog_entries().await;
    let mut items = String::new();
    if entries.is_empty() {
        items.push_str("<p class=\"blog-empty\">Belum ada artikel.</p>");
    } else {
        for entry in &entries {
            items.push_str(&format!(
                "<article class=\"blog-card\"><p class=\"blog-date\">{}</p><h2><a href=\"/blog/{}.html\">{}</a></h2><p>{}</p></article>",
                escape_html(&entry.date_display),
                entry.slug,
                escape_html(&entry.title),
                escape_html(&entry.description),
            ));
        }
    }
    let html = format!(
        r##"<!doctype html>
<html lang="id">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Blog Rajacek — Artikel Validasi Rekening, E-Wallet, WhatsApp &amp; PLN</title>
    <meta name="description" content="Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya." />
    <meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1" />
    <meta name="author" content="PT DATA BRIDGE NUSANTARA" />
    <link rel="canonical" href="https://www.rajacek.com/blog/" />
    <link rel="icon" href="/favicon.png" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Rajacek" />
    <meta property="og:locale" content="id_ID" />
    <meta property="og:title" content="Blog Rajacek — Artikel Validasi Rekening, E-Wallet, WhatsApp &amp; PLN" />
    <meta property="og:description" content="Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya." />
    <meta property="og:url" content="https://www.rajacek.com/blog/" />
    <meta property="og:image" content="https://www.rajacek.com/og-cover.png" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="Blog Rajacek — Artikel Validasi Rekening, E-Wallet, WhatsApp &amp; PLN" />
    <meta name="twitter:description" content="Artikel dari Rajacek tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya." />
    <meta name="twitter:image" content="https://www.rajacek.com/og-cover.png" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/landing.css?v=20261025-5" />
    <style>
      .blog-list {{ width:min(760px,calc(100% - 40px)); margin:auto; padding:48px 0 72px; }}
      .blog-list h1 {{ color:var(--navy); font-size:clamp(31px,4vw,46px); line-height:1.12; letter-spacing:-2px; margin-bottom:12px; }}
      .blog-list .lede {{ color:var(--muted); font-size:16px; margin-bottom:36px; }}
      .blog-card {{ padding:24px 0; border-top:1px solid var(--line); }}
      .blog-card:last-child {{ border-bottom:1px solid var(--line); }}
      .blog-date {{ color:var(--muted); font-size:13px; margin:0 0 6px; }}
      .blog-card h2 {{ font-size:21px; letter-spacing:-.5px; margin:0 0 8px; }}
      .blog-card h2 a:hover {{ color:var(--blue); }}
      .blog-card p:last-child {{ color:var(--muted); font-size:15px; margin:0; }}
      .blog-empty {{ color:var(--muted); }}
      @media (max-width:480px) {{ .blog-list {{ width:calc(100% - 28px); padding:36px 0 56px; }} }}
    </style>
  </head>
  <body>
    <a class="skip-link" href="#content">Lewati ke konten utama</a>
    <header class="site-header">
      <a class="brand" href="/" aria-label="Rajacek, beranda"><img class="brand-mark-img" src="/logo-mark.png" alt="" aria-hidden="true"><span>aja<span>cek</span></span></a>
      <nav aria-label="Navigasi utama"><a href="/">Beranda</a><a href="/docs">Dokumentasi</a><a href="/blog/">Blog</a></nav>
      <a class="nav-cta" href="/member">Masuk dashboard <span aria-hidden="true">→</span></a>
    </header>
    <main id="content">
      <div class="blog-list">
        <h1>Blog Rajacek</h1>
        <p class="lede">Artikel tentang validasi rekening bank, e-wallet, WhatsApp, dan ID pelanggan PLN — pengertian, cara kerja, dan manfaatnya.</p>
        {items}
      </div>
    </main>
    <footer><a class="brand" href="/" aria-label="Rajacek, beranda"><img class="brand-mark-img" src="/logo-mark.png" alt="" aria-hidden="true"><span>aja<span>cek</span></span></a><p>© 2026 Rajacek · PT DATA BRIDGE NUSANTARA — Infrastruktur validasi untuk Indonesia.<br><span class="foot-contact">Hubungi kami: <a href="mailto:apivalidasi@gmail.com">apivalidasi@gmail.com</a> · <a href="https://t.me/xyz_yaz" target="_blank" rel="noopener">Telegram @xyz_yaz</a></span></p></footer>
  </body>
</html>"##,
        items = items
    );
    Html(html).into_response()
}

/// `GET /blog/:slug`: one article file, served as-is. Unknown or invalid
/// slugs get the branded 404 page (never a file outside `web/blog/`).
pub async fn blog_article(Path(raw): Path<String>) -> Response {
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
            },
            BlogEntry {
                slug: "validasi-nomor-rekening".to_string(),
                title: "Rekening".to_string(),
                description: "d".to_string(),
                date: "2026-10-27".to_string(),
                date_display: "27 Oktober 2026".to_string(),
            },
            BlogEntry {
                slug: "lama".to_string(),
                title: "Lama".to_string(),
                description: "d".to_string(),
                date: "2026-10-20".to_string(),
                date_display: "20 Oktober 2026".to_string(),
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
}
