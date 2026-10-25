//! Analitik admin riil + monitor kesehatan rute (AREA 1+2).
//!
//! Aturan yang dipegang modul ini:
//! - Tanpa migrasi: semua agregasi memakai tabel yang sudah ada
//!   (`package_orders`, `validation_requests`) dan state guard in-memory.
//! - Tanpa nama/URL/kode upstream di respons: rute diidentifikasi hanya
//!   dengan id internal + label yang dikonfigurasi admin sendiri; kolom
//!   `base_url` tidak pernah disalin ke DTO kesehatan.
//! - Semua query bertanggal dan berbatas: rentang analitik di-clamp
//!   (default 30 hari, maks 90), jendela kesehatan 24 jam terakhir,
//!   sampel latensi per produk dibatasi 5.000 baris terbaru.
//!
//! Definisi pendapatan (didokumentasikan, bukan ditebak):
//! `total_idr` analitik = SUM(amount_idr) order berstatus `paid` atau
//! `granted` DALAM rentang yang diminta. Status lain TIDAK dihitung:
//! `waiting_payment` (belum bayar), `expired`/`canceled` (tidak jadi),
//! `needs_review` (bukti lunas belum diputuskan — konservatif: order
//! `needs_review` yang terbukti lunas akan berubah menjadi `granted`
//! lewat resolve admin dan baru saat itu masuk pendapatan).
//! Karena itu `total_idr` SELALU sama dengan jumlah `per_day`
//! (keduanya dari jendela yang sama); total sepanjang masa tetap ada
//! di kartu dashboard overview (`estimated_revenue`).
//!
//! Definisi success rate per produk: pembilang = outcome `valid` +
//! `not_kyc` (keduanya jawaban final yang "berhasil dijawab"),
//! penyebut = outcome final saja (`valid`, `invalid`, `not_found`,
//! `not_kyc`). Outcome non-final (`pending`, `provider_error`,
//! `rate_limited`, `quota_exhausted`) tidak masuk penyebut.
//! CATATAN: kolom `outcome` di `validation_requests` (migrasi 0001)
//! enum-nya belum memuat `not_kyc`, sehingga baris `not_kyc` yang
//! ditulis worker lewat INSERT IGNORE saat ini tidak tersimpan sebagai
//! `not_kyc` dan terbaca 0 di agregasi ini. Query tetap menghitung
//! `not_kyc` secara eksplisit agar angka menjadi benar begitu enum
//! diperluas (perlu migrasi — di luar area ini, JANGAN ditambah di
//! sini). Jangan pernah menebak baris outcome kosong sebagai `not_kyc`.
//!
//! Kesehatan per rute: ledger TIDAK menyimpan id rute, jadi latensi /
//! success rate / error per rute tidak bisa diatribusikan dari ledger
//! dan dikembalikan null; yang per rute (dari guard in-memory) adalah
//! status circuit breaker + jumlah kegagalan beruntun + flag aktif.
//! Latensi (rata-rata/p95), success rate, dan jumlah error terakhir
//! tersedia per PRODUK dari ledger 24 jam terakhir.

use std::collections::HashMap;

use chrono::{Datelike, FixedOffset, NaiveDate, Utc};
use serde::Serialize;
use sqlx::MySqlPool;

use crate::{
    models::{ProviderEndpoint, ValidationProduct},
    provider_guard::GuardEndpointStatus,
};

/// Status order yang dihitung sebagai pendapatan (lihat header modul).
pub const REVENUE_STATUSES: [&str; 2] = ["paid", "granted"];

/// Rentang analitik bawaan (hari) bila parameter `days` tidak diisi.
pub const ANALYTICS_DEFAULT_DAYS: i64 = 30;

/// Rentang analitik maksimum (hari). Query tanpa batas dilarang: dashboard
/// tidak boleh memindai `validation_requests` tanpa batas waktu.
pub const ANALYTICS_MAX_DAYS: i64 = 90;

/// Jendela agregasi kesehatan (jam terakhir).
pub const HEALTH_WINDOW_HOURS: i64 = 24;

/// Sampel latensi terbaru per produk untuk p95 (batas keras, anti beban).
pub const HEALTH_LATENCY_SAMPLE_LIMIT: i64 = 5_000;

/// TTL cache analitik di `AdminStore` (detik). Kesehatan TIDAK di-cache:
/// status breaker harus selalu live.
pub const ANALYTICS_CACHE_TTL_SECS: u64 = 60;

/// Produk yang selalu tampil meski tanpa data (tidak crash).
const KNOWN_PRODUCTS: [ValidationProduct; 3] = [
    ValidationProduct::BankAccount,
    ValidationProduct::Ewallet,
    ValidationProduct::Whatsapp,
];

/// `true` hanya untuk status order yang dihitung sebagai pendapatan.
pub fn is_revenue_status(status: &str) -> bool {
    REVENUE_STATUSES.contains(&status)
}

/// Clamp rentang analitik: kosong -> default, di bawah 1 -> 1,
/// di atas maksimum -> maksimum.
pub fn clamp_analytics_days(days: Option<i64>) -> i64 {
    days.unwrap_or(ANALYTICS_DEFAULT_DAYS).clamp(1, ANALYTICS_MAX_DAYS)
}

/// Success rate (persen) dari hitungan sukses vs total final.
/// `None` bila tidak ada outcome final (produk tanpa data) — pemanggil
/// menampilkannya sebagai "—", bukan 0% yang menyesatkan.
pub fn success_rate_percent(success_hits: u64, final_hits: u64) -> Option<f32> {
    if final_hits == 0 {
        None
    } else {
        Some(success_hits as f32 / final_hits as f32 * 100.0)
    }
}

/// Persentil nearest-rank atas nilai yang SUDAH terurut menaik.
/// `pct` dalam 0..=100. `None` untuk sampel kosong.
pub fn percentile_sorted(sorted_ascending: &[u64], pct: f64) -> Option<u64> {
    if sorted_ascending.is_empty() {
        return None;
    }
    let pct = pct.clamp(0.0, 100.0);
    let rank = (pct / 100.0 * sorted_ascending.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted_ascending.len() - 1);
    Some(sorted_ascending[index])
}

/// Rata-rata + p95 dari sampel latensi (urutan input bebas).
/// Mengembalikan `(None, None)` untuk sampel kosong.
pub fn latency_summary(mut latencies: Vec<u64>) -> (Option<u64>, Option<u64>) {
    if latencies.is_empty() {
        return (None, None);
    }
    let sum: u64 = latencies.iter().sum();
    let avg = sum / latencies.len() as u64;
    latencies.sort_unstable();
    (Some(avg), percentile_sorted(&latencies, 95.0))
}

/// Batas bawah jendela (UTC, NaiveDateTime) untuk kolom `occurred_at` /
/// `paid_at`/`created_at` yang disimpan sebagai UTC: tengah malam WIB
/// hari pertama jendela, dikonversi ke UTC.
fn window_start_utc(days: i64) -> chrono::NaiveDateTime {
    let wib = FixedOffset::east_opt(7 * 3600).expect("offset WIB valid");
    let today = Utc::now().with_timezone(&wib).date_naive();
    let first_day = today - chrono::Duration::days(days - 1);
    let midnight_wib = first_day
        .and_hms_opt(0, 0, 0)
        .expect("tengah malam valid");
    // WIB = UTC+7, jadi UTC = WIB - 7 jam.
    midnight_wib - chrono::Duration::hours(7)
}

/// Daftar hari WIB (NaiveDate) dalam jendela, untuk zero-fill di Rust.
fn wib_day_list(days: i64) -> Vec<NaiveDate> {
    let wib = FixedOffset::east_opt(7 * 3600).expect("offset WIB valid");
    let today = Utc::now().with_timezone(&wib).date_naive();
    (0..days)
        .rev()
        .map(|offset| today - chrono::Duration::days(offset))
        .collect()
}

fn day_label(day: NaiveDate) -> String {
    // Label ringkas "12 Okt" untuk grafik; kunci agregasi tetap %Y-%m-%d.
    const MONTH_ID: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des",
    ];
    format!("{} {}", day.day(), MONTH_ID[(day.month() - 1) as usize])
}

// ---------------------------------------------------------------------------
// DTO analitik
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct DailyRevenue {
    pub day: String,
    pub label: String,
    pub revenue_idr: u64,
    pub orders: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RevenueAnalytics {
    /// Total dalam rentang yang diminta (= jumlah `per_day`, invarian).
    pub total_idr: u64,
    pub total_orders: u64,
    pub per_day: Vec<DailyRevenue>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProductAnalytics {
    pub product: String,
    pub product_label: String,
    pub total_hits: u64,
    pub final_hits: u64,
    pub success_hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_rate_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_latency_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DailyHits {
    pub day: String,
    pub product: String,
    pub hits: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalyticsResponse {
    pub days: i64,
    pub generated_at: chrono::DateTime<Utc>,
    /// `true` bila respons ini dari cache 60 detik (bukan query baru).
    pub cached: bool,
    /// `false` bila tidak ada pool database (mode memori): angka nol
    /// berarti "tidak diketahui", bukan "tidak ada trafik".
    pub database: bool,
    pub revenue: RevenueAnalytics,
    pub products: Vec<ProductAnalytics>,
    pub hits_per_day: Vec<DailyHits>,
}

impl AnalyticsResponse {
    /// Respons kosong untuk mode tanpa database: tidak crash, tidak
    /// berpura-pura punya angka.
    pub fn empty(days: i64) -> Self {
        let day_list = wib_day_list(days);
        let products = KNOWN_PRODUCTS
            .iter()
            .map(|product| ProductAnalytics {
                product: product.as_str().to_owned(),
                product_label: product.label_id().to_owned(),
                total_hits: 0,
                final_hits: 0,
                success_hits: 0,
                success_rate_percent: None,
                avg_latency_ms: None,
            })
            .collect();
        let hits_per_day = day_list
            .iter()
            .flat_map(|day| {
                let key = day.format("%Y-%m-%d").to_string();
                KNOWN_PRODUCTS.iter().map(move |product| DailyHits {
                    day: key.clone(),
                    product: product.as_str().to_owned(),
                    hits: 0,
                })
            })
            .collect();
        AnalyticsResponse {
            days,
            generated_at: Utc::now(),
            cached: false,
            database: false,
            revenue: RevenueAnalytics {
                total_idr: 0,
                total_orders: 0,
                per_day: day_list
                    .iter()
                    .map(|day| DailyRevenue {
                        day: day.format("%Y-%m-%d").to_string(),
                        label: day_label(*day),
                        revenue_idr: 0,
                        orders: 0,
                    })
                    .collect(),
            },
            products,
            hits_per_day,
        }
    }
}

/// Zero-fill pendapatan harian: setiap hari jendela muncul tepat sekali,
/// hari tanpa order = 0. `total_idr` = jumlah `per_day` (invarian).
fn build_revenue(
    rows: Vec<(String, u64, i64)>,
    day_list: &[NaiveDate],
) -> RevenueAnalytics {
    let by_day: HashMap<String, (u64, u64)> = rows
        .into_iter()
        .map(|(day, revenue, orders)| (day, (revenue, orders.max(0) as u64)))
        .collect();
    let mut per_day = Vec::with_capacity(day_list.len());
    let mut total_idr = 0u64;
    let mut total_orders = 0u64;
    for day in day_list {
        let key = day.format("%Y-%m-%d").to_string();
        let (revenue, orders) = by_day.get(&key).copied().unwrap_or((0, 0));
        total_idr = total_idr.saturating_add(revenue);
        total_orders = total_orders.saturating_add(orders);
        per_day.push(DailyRevenue {
            day: key,
            label: day_label(*day),
            revenue_idr: revenue,
            orders,
        });
    }
    RevenueAnalytics {
        total_idr,
        total_orders,
        per_day,
    }
}

/// Zero-fill hit harian per produk: setiap (hari, produk) muncul tepat
/// sekali. Produk yang dikenal selalu ada; kode produk lain yang muncul
/// di baris ikut ditambahkan (tidak pernah crash karena kode baru).
fn build_hits_per_day(
    rows: Vec<(String, String, i64)>,
    day_list: &[NaiveDate],
    extra_products: &[String],
) -> Vec<DailyHits> {
    let mut products: Vec<String> = KNOWN_PRODUCTS
        .iter()
        .map(|product| product.as_str().to_owned())
        .collect();
    for extra in extra_products {
        if !products.contains(extra) {
            products.push(extra.clone());
        }
    }
    let by_key: HashMap<(String, String), u64> = rows
        .into_iter()
        .map(|(day, product, hits)| ((day, product), hits.max(0) as u64))
        .collect();
    let mut out = Vec::with_capacity(day_list.len() * products.len());
    for day in day_list {
        let key = day.format("%Y-%m-%d").to_string();
        for product in &products {
            out.push(DailyHits {
                day: key.clone(),
                product: product.clone(),
                hits: by_key
                    .get(&(key.clone(), product.clone()))
                    .copied()
                    .unwrap_or(0),
            });
        }
    }
    out
}

fn product_label_for(code: &str) -> String {
    match code {
        "bank_account" => ValidationProduct::BankAccount.label_id().to_owned(),
        "ewallet" => ValidationProduct::Ewallet.label_id().to_owned(),
        "whatsapp" => ValidationProduct::Whatsapp.label_id().to_owned(),
        other => other.to_owned(),
    }
}

/// Gabungkan agregat per produk dari SQL menjadi daftar produk:
/// produk yang dikenal selalu ada (nol bila tanpa data).
fn build_product_analytics(
    rows: Vec<(String, i64, i64, i64, f64)>,
) -> Vec<ProductAnalytics> {
    let mut by_product: HashMap<String, (u64, u64, u64, Option<u64>)> = HashMap::new();
    for (code, total, success, final_hits, avg_latency) in rows {
        by_product.insert(
            code,
            (
                total.max(0) as u64,
                success.max(0) as u64,
                final_hits.max(0) as u64,
                if total > 0 {
                    Some(avg_latency.max(0.0) as u64)
                } else {
                    None
                },
            ),
        );
    }
    let mut codes: Vec<String> = KNOWN_PRODUCTS
        .iter()
        .map(|product| product.as_str().to_owned())
        .collect();
    for code in by_product.keys() {
        if !codes.contains(code) {
            codes.push(code.clone());
        }
    }
    codes.sort();
    codes
        .into_iter()
        .map(|code| {
            let (total, success, final_hits, avg) =
                by_product.get(&code).copied().unwrap_or((0, 0, 0, None));
            ProductAnalytics {
                product_label: product_label_for(&code),
                product: code,
                total_hits: total,
                final_hits,
                success_hits: success,
                success_rate_percent: success_rate_percent(success, final_hits),
                avg_latency_ms: avg,
            }
        })
        .collect()
}

/// Agregasi analitik dari database. `None` bila ada query yang gagal
/// (pemanggil mengembalikan error, bukan angka parsial yang menyesatkan).
pub async fn analytics_from_db(pool: &MySqlPool, days: i64) -> Option<AnalyticsResponse> {
    let days = clamp_analytics_days(Some(days));
    let start = window_start_utc(days);
    let day_list = wib_day_list(days);

    // Pendapatan per hari (WIB) dari order lunas/ter-grant saja.
    // COALESCE(paid_at, created_at): order `paid`/`granted` selalu punya
    // paid_at; fallback hanya pengaman baris warisan.
    let revenue_rows: Vec<(String, u64, i64)> = sqlx::query_as(
        "SELECT DATE_FORMAT(CONVERT_TZ(COALESCE(paid_at, created_at), '+00:00', '+07:00'), '%Y-%m-%d') AS day, \
         CAST(COALESCE(SUM(amount_idr), 0) AS UNSIGNED), COUNT(*) \
         FROM package_orders \
         WHERE status IN ('paid', 'granted') AND COALESCE(paid_at, created_at) >= ? \
         GROUP BY day ORDER BY day",
    )
    .bind(start)
    .fetch_all(pool)
    .await
    .ok()?;
    let revenue = build_revenue(revenue_rows, &day_list);

    // Hit per hari per produk (semua outcome) dari validation_requests.
    let hit_rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT DATE_FORMAT(CONVERT_TZ(occurred_at, '+00:00', '+07:00'), '%Y-%m-%d') AS day, \
         product_code, COUNT(*) FROM validation_requests \
         WHERE occurred_at >= ? GROUP BY day, product_code ORDER BY day, product_code",
    )
    .bind(start)
    .fetch_all(pool)
    .await
    .ok()?;
    let extra_products: Vec<String> = hit_rows
        .iter()
        .map(|(_, product, _)| product.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let hits_per_day = build_hits_per_day(hit_rows, &day_list, &extra_products);

    // Agregat per produk: total, sukses (valid+not_kyc), final, rata-rata.
    let product_rows: Vec<(String, i64, i64, i64, f64)> = sqlx::query_as(
        "SELECT product_code, COUNT(*), \
         CAST(COALESCE(SUM(outcome IN ('valid', 'not_kyc')), 0) AS SIGNED), \
         CAST(COALESCE(SUM(outcome IN ('valid', 'invalid', 'not_found', 'not_kyc')), 0) AS SIGNED), \
         CAST(COALESCE(AVG(provider_latency_ms), 0) AS DOUBLE) \
         FROM validation_requests WHERE occurred_at >= ? GROUP BY product_code",
    )
    .bind(start)
    .fetch_all(pool)
    .await
    .ok()?;
    let products = build_product_analytics(product_rows);

    Some(AnalyticsResponse {
        days,
        generated_at: Utc::now(),
        cached: false,
        database: true,
        revenue,
        products,
        hits_per_day,
    })
}

// ---------------------------------------------------------------------------
// DTO kesehatan rute
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
pub struct RouteHealth {
    /// Id internal rute (UUID). Tidak ada URL/nama upstream di sini.
    pub endpoint_id: String,
    pub product: String,
    pub product_label: String,
    /// Label yang dikonfigurasi admin untuk rute ini (bukan nama vendor).
    pub route_label: String,
    pub active: bool,
    /// "closed" | "open" | "half_open" | "unknown" (tanpa guard, mis. demo).
    pub circuit: String,
    pub consecutive_failures: u32,
    /// Selalu null: ledger tidak menyimpan id rute, jadi latensi per rute
    /// tidak bisa diatribusikan (lihat header modul).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_rate_percent: Option<f32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProductHealth {
    pub product: String,
    pub product_label: String,
    pub total_hits: u64,
    pub provider_errors: u64,
    pub final_hits: u64,
    pub success_hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_rate_percent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_latency_ms: Option<u64>,
    /// p95 atas maksimal 5.000 latensi terbaru produk ini dalam jendela.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_latency_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProvidersHealthResponse {
    pub generated_at: chrono::DateTime<Utc>,
    pub window_hours: i64,
    /// `false` bila agregat ledger gagal dibaca: data breaker tetap live,
    /// angka ledger kosong (bukan angka palsu).
    pub ledger_available: bool,
    pub products: Vec<ProductHealth>,
    pub routes: Vec<RouteHealth>,
}

/// Gabungkan snapshot breaker guard dengan katalog rute menjadi tabel
/// kesehatan per rute. Rute tanpa entri guard = breaker tertutup, 0 gagal.
/// Entri guard untuk rute yang sudah dihapus diabaikan.
fn build_route_health(
    endpoints: &[ProviderEndpoint],
    guard_snapshot: Option<&[GuardEndpointStatus]>,
) -> Vec<RouteHealth> {
    let by_id: HashMap<String, &GuardEndpointStatus> = guard_snapshot
        .unwrap_or(&[])
        .iter()
        .map(|entry| (entry.endpoint_id.clone(), entry))
        .collect();
    endpoints
        .iter()
        .map(|endpoint| {
            let (circuit, failures) = match by_id.get(&endpoint.id.to_string()) {
                Some(entry) => (entry.circuit.to_owned(), entry.consecutive_failures),
                None => (
                    if guard_snapshot.is_some() {
                        "closed".to_owned()
                    } else {
                        "unknown".to_owned()
                    },
                    0,
                ),
            };
            RouteHealth {
                endpoint_id: endpoint.id.to_string(),
                product: endpoint.product.as_str().to_owned(),
                product_label: endpoint.product.label_id().to_owned(),
                route_label: endpoint.name.clone(),
                active: endpoint.active,
                circuit,
                consecutive_failures: failures,
                avg_latency_ms: None,
                p95_latency_ms: None,
                success_rate_percent: None,
            }
        })
        .collect()
}

/// Kesehatan rute + produk. Ledger dibaca toleran-gagal per query:
/// bila ledger tidak bisa dibaca, produk tetap tampil dengan angka kosong
/// dan `ledger_available = false`, sementara data breaker tetap live.
pub async fn providers_health(
    pool: Option<&MySqlPool>,
    endpoints: &[ProviderEndpoint],
    guard_snapshot: Option<Vec<GuardEndpointStatus>>,
) -> ProvidersHealthResponse {
    let routes = build_route_health(endpoints, guard_snapshot.as_deref());
    let mut products: Vec<ProductHealth> = KNOWN_PRODUCTS
        .iter()
        .map(|product| ProductHealth {
            product: product.as_str().to_owned(),
            product_label: product.label_id().to_owned(),
            total_hits: 0,
            provider_errors: 0,
            final_hits: 0,
            success_hits: 0,
            success_rate_percent: None,
            avg_latency_ms: None,
            p95_latency_ms: None,
        })
        .collect();
    let mut ledger_available = false;
    if let Some(pool) = pool {
        let start = Utc::now().naive_utc() - chrono::Duration::hours(HEALTH_WINDOW_HOURS);
        // Agregat per produk 24 jam terakhir (satu query, GROUP BY).
        if let Ok(rows) = sqlx::query_as::<_, (String, i64, i64, i64, i64, f64)>(
            "SELECT product_code, COUNT(*), \
             CAST(COALESCE(SUM(outcome = 'provider_error'), 0) AS SIGNED), \
             CAST(COALESCE(SUM(outcome IN ('valid', 'not_kyc')), 0) AS SIGNED), \
             CAST(COALESCE(SUM(outcome IN ('valid', 'invalid', 'not_found', 'not_kyc')), 0) AS SIGNED), \
             CAST(COALESCE(AVG(provider_latency_ms), 0) AS DOUBLE) \
             FROM validation_requests WHERE occurred_at >= ? GROUP BY product_code",
        )
        .bind(start)
        .fetch_all(pool)
        .await
        {
            ledger_available = true;
            let mut by_product: HashMap<String, (u64, u64, u64, u64, Option<u64>)> =
                HashMap::new();
            for (code, total, errors, success, final_hits, avg) in rows {
                by_product.insert(
                    code,
                    (
                        total.max(0) as u64,
                        errors.max(0) as u64,
                        success.max(0) as u64,
                        final_hits.max(0) as u64,
                        if total > 0 {
                            Some(avg.max(0.0) as u64)
                        } else {
                            None
                        },
                    ),
                );
            }
            for entry in products.iter_mut() {
                if let Some((total, errors, success, final_hits, avg)) =
                    by_product.get(&entry.product).copied()
                {
                    entry.total_hits = total;
                    entry.provider_errors = errors;
                    entry.success_hits = success;
                    entry.final_hits = final_hits;
                    entry.success_rate_percent =
                        success_rate_percent(success, final_hits);
                    entry.avg_latency_ms = avg;
                }
            }
            // p95 per produk: sampel terbaru saja (batas keras).
            for entry in products.iter_mut() {
                if entry.total_hits == 0 {
                    continue;
                }
                if let Ok(samples) = sqlx::query_scalar::<_, u64>(
                    "SELECT provider_latency_ms FROM validation_requests \
                     WHERE product_code = ? AND occurred_at >= ? \
                     ORDER BY occurred_at DESC LIMIT ?",
                )
                .bind(&entry.product)
                .bind(start)
                .bind(HEALTH_LATENCY_SAMPLE_LIMIT)
                .fetch_all(pool)
                .await
                {
                    entry.p95_latency_ms = latency_summary(samples).1;
                }
            }
        }
    }
    ProvidersHealthResponse {
        generated_at: Utc::now(),
        window_hours: HEALTH_WINDOW_HOURS,
        ledger_available,
        products,
        routes,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_hits_per_day, build_product_analytics, build_revenue, build_route_health,
        clamp_analytics_days, is_revenue_status, latency_summary, percentile_sorted,
        success_rate_percent, wib_day_list, ANALYTICS_DEFAULT_DAYS, ANALYTICS_MAX_DAYS,
    };
    use crate::{
        models::{ProviderEndpoint, ProviderRequestMode, ProviderResponseMapping, ValidationProduct},
        provider_guard::GuardEndpointStatus,
    };
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn revenue_statuses_only_paid_and_granted() {
        assert!(is_revenue_status("paid"));
        assert!(is_revenue_status("granted"));
        for status in [
            "waiting_payment",
            "expired",
            "canceled",
            "needs_review",
            "rejected",
            "",
        ] {
            assert!(!is_revenue_status(status), "{status} must not count as revenue");
        }
    }

    #[test]
    fn analytics_days_are_clamped() {
        assert_eq!(clamp_analytics_days(None), ANALYTICS_DEFAULT_DAYS);
        assert_eq!(clamp_analytics_days(Some(0)), 1);
        assert_eq!(clamp_analytics_days(Some(-5)), 1);
        assert_eq!(clamp_analytics_days(Some(7)), 7);
        assert_eq!(clamp_analytics_days(Some(ANALYTICS_MAX_DAYS + 500)), ANALYTICS_MAX_DAYS);
    }

    #[test]
    fn revenue_total_equals_sum_of_daily() {
        let days = wib_day_list(3);
        let first = days[0].format("%Y-%m-%d").to_string();
        let third = days[2].format("%Y-%m-%d").to_string();
        let revenue = build_revenue(
            vec![(first, 150_000, 2), (third, 50_000, 1)],
            &days,
        );
        // Hari tengah tanpa order tetap muncul dengan 0 (zero-fill).
        assert_eq!(revenue.per_day.len(), 3);
        assert_eq!(revenue.per_day[1].revenue_idr, 0);
        assert_eq!(revenue.per_day[1].orders, 0);
        assert_eq!(revenue.total_idr, 200_000);
        assert_eq!(
            revenue.total_idr,
            revenue.per_day.iter().map(|day| day.revenue_idr).sum::<u64>()
        );
        assert_eq!(revenue.total_orders, 3);
    }

    #[test]
    fn product_without_data_does_not_crash_and_has_no_rate() {
        let products = build_product_analytics(vec![]);
        assert_eq!(products.len(), 3);
        for product in &products {
            assert_eq!(product.total_hits, 0);
            assert_eq!(product.success_rate_percent, None);
            assert_eq!(product.avg_latency_ms, None);
        }
    }

    #[test]
    fn success_rate_counts_valid_plus_not_kyc_over_final_only() {
        // valid 70 + not_kyc 10 sukses, final 100 -> 80%.
        assert_eq!(success_rate_percent(80, 100), Some(80.0));
        assert_eq!(success_rate_percent(0, 0), None);
        let products = build_product_analytics(vec![(
            "ewallet".to_owned(),
            150, // total (termasuk 50 non-final: pending/error)
            80,  // valid + not_kyc
            100, // final saja
            120.0,
        )]);
        let ewallet = products
            .iter()
            .find(|product| product.product == "ewallet")
            .expect("ewallet row");
        assert_eq!(ewallet.total_hits, 150);
        assert_eq!(ewallet.final_hits, 100);
        assert_eq!(ewallet.success_rate_percent, Some(80.0));
        assert_eq!(ewallet.avg_latency_ms, Some(120));
    }

    #[test]
    fn hits_per_day_zero_fills_every_product_every_day() {
        let days = wib_day_list(2);
        let first = days[0].format("%Y-%m-%d").to_string();
        let hits = build_hits_per_day(
            vec![(first.clone(), "bank_account".to_owned(), 5)],
            &days,
            &[],
        );
        assert_eq!(hits.len(), 2 * 3);
        let known = hits
            .iter()
            .find(|row| row.day == first && row.product == "bank_account")
            .expect("known cell");
        assert_eq!(known.hits, 5);
        assert!(hits
            .iter()
            .filter(|row| row.product == "whatsapp")
            .all(|row| row.hits == 0));
    }

    #[test]
    fn percentile_and_latency_summary() {
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile_sorted(&sorted, 95.0), Some(95));
        assert_eq!(percentile_sorted(&[], 95.0), None);
        assert_eq!(percentile_sorted(&[10], 95.0), Some(10));
        let (avg, p95) = latency_summary(vec![300, 100, 200]);
        assert_eq!(avg, Some(200));
        assert_eq!(p95, Some(300));
        assert_eq!(latency_summary(vec![]), (None, None));
    }

    fn test_endpoint(id: Uuid, product: ValidationProduct, active: bool) -> ProviderEndpoint {
        ProviderEndpoint {
            id,
            product,
            name: "Rute uji".to_owned(),
            base_url: "https://internal.example.invalid/".to_owned(),
            timeout_ms: 5000,
            request_mode: ProviderRequestMode::Generic,
            auth_header: "X-Test".to_owned(),
            active,
            api_key_configured: false,
            response_mapping: ProviderResponseMapping::default_for(product),
            service_code_mapping: std::collections::HashMap::new(),
            http_method: "POST".to_owned(),
            code_param: "code".to_owned(),
            number_param: "number".to_owned(),
            key_param: None,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn open_breaker_shows_open_and_missing_route_is_closed() {
        let open_id = Uuid::now_v7();
        let quiet_id = Uuid::now_v7();
        let routes = build_route_health(
            &[
                test_endpoint(open_id, ValidationProduct::BankAccount, true),
                test_endpoint(quiet_id, ValidationProduct::Ewallet, false),
            ],
            Some(&[GuardEndpointStatus {
                endpoint_id: open_id.to_string(),
                product: ValidationProduct::BankAccount,
                circuit: "open",
                consecutive_failures: 5,
            }]),
        );
        let open = routes
            .iter()
            .find(|route| route.endpoint_id == open_id.to_string())
            .expect("open route");
        assert_eq!(open.circuit, "open");
        assert_eq!(open.consecutive_failures, 5);
        assert!(open.active);
        // Rute tanpa entri guard tidak crash: tertutup, 0 gagal.
        let quiet = routes
            .iter()
            .find(|route| route.endpoint_id == quiet_id.to_string())
            .expect("quiet route");
        assert_eq!(quiet.circuit, "closed");
        assert_eq!(quiet.consecutive_failures, 0);
        assert!(!quiet.active);
        // Tidak ada URL upstream di DTO kesehatan.
        assert!(!format!("{routes:?}").contains("internal.example.invalid"));
    }

    #[test]
    fn health_without_guard_reports_unknown_circuit() {
        let routes = build_route_health(
            &[test_endpoint(
                Uuid::now_v7(),
                ValidationProduct::Whatsapp,
                true,
            )],
            None,
        );
        assert_eq!(routes[0].circuit, "unknown");
    }
}
