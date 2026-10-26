//! Multi-admin dengan peran (area 7+8).
//!
//! # Mekanisme identitas admin hari ini (dibaca dari kode, 2026-10-25)
//!
//! Identitas admin TIDAK ditentukan tabel ini. Satu-satunya gerbang
//! login tetap `auth::require_admin` (lihat `src/auth.rs`):
//!
//! * Google OAuth: callback (`google_login_callback`) menolak email
//!   yang tidak ada di `ADMIN_GOOGLE_EMAILS` (env, diparse lowercase
//!   menjadi `AppConfig::admin_google_emails`). JWT sesi yang diterbitkan
//!   membawa `role = "admin"` generik — tidak ada peran bertingkat.
//! * Token pengembangan (bukan production): header `x-admin-token`
//!   yang cocok dengan `DEVELOPMENT_ADMIN_TOKEN` menghasilkan
//!   principal dengan email `admin@local.dev`.
//! * Login lokal (mode development saja): satu akun admin lokal.
//!
//! Modul ini hanya menentukan PERAN sebuah sesi yang SUDAH lolos
//! gerbang di atas. Konsekuensinya: menambahkan baris `admins` untuk
//! email yang belum ada di allowlist Google TIDAK memberinya akses
//! masuk; email itu tetap harus ditambahkan ke `ADMIN_GOOGLE_EMAILS`
//! (atau memakai jalur dev yang berlaku). Mengganti allowlist dengan
//! tabel ini adalah keputusan koordinator, sengaja tidak dilakukan di
//! patch ini agar tidak melemahkan gerbang login yang sudah ada.
//!
//! # Seed / fallback anti-kunci (keputusan desain)
//!
//! Semua email admin yang sah menurut mekanisme lama adalah OWNER.
//! Itu diwujudkan dua lapis, keduanya INSERT IGNORE sehingga tidak
//! pernah menimpa peran yang sudah diatur owner:
//!
//! 1. Seed eksplisit saat startup: `main.rs` memanggil
//!    `AdminStore::seed_legacy_admins` dengan isi
//!    `ADMIN_GOOGLE_EMAILS` begitu pool terpasang.
//! 2. Fallback malas di `resolve_admin_role`: sesi yang lolos cek lama
//!    tetapi belum punya baris `admins` diperlakukan sebagai OWNER,
//!    baris owner-nya disisipkan best-effort, dan kejadian itu
//!    ditulis ke log (peringatan). Jadi admin lama TIDAK PERNAH
//!    terkunci — bahkan bila migrasi 0019 belum jalan atau seed
//!    startup terlewat — selama sesinya lolos cek lama, KECUALI
//!    emailnya sengaja dihapus lewat panel: email di tombstone
//!    `deleted_admins` (migrasi 0028, perbaikan R1) ditolak 403
//!    sebelum fallback dan tidak pernah di-seed kembali.

//!
//! Mode tanpa database (memory-only, dev/tes): tidak ada baris yang
//! bisa dibaca, sehingga setiap sesi admin yang sah jatuh ke fallback
//! owner, sama seperti perilaku sebelum patch ini (semua admin setara).
//!
//! # Signatur untuk koordinator (dipakai `api.rs`)
//!
//! ```text
//! pub async fn require_role(
//!     store: &AdminStore,
//!     principal: &AdminPrincipal,
//!     min_role: Role,
//! ) -> Result<Role, AppError>
//! ```
//! Mengembalikan peran teresolusi bila `peran >= min_role`, atau
//! `AppError::forbidden` (HTTP 403) bila peran kurang atau akun
//! dinonaktifkan. `api.rs` membungkusnya dalam
//! `require_admin_role(state, headers, min_role)` yang mengembalikan
//! `AdminPrincipal` (setelah cek sesi + revocation + peran) agar
//! handler yang sudah ada tidak berubah bentuk.
//!
//! Hierarki (lihat `Role::rank`): viewer (0) < support (1) <
//! manager (2) < owner (3).
//!
//! Pemetaan endpoint yang sudah ada (lihat `api.rs`):
//! * GET/read-only -> viewer (termasuk GET /v1/admin/activity,
//!   kesehatan provider, kesehatan stream, daftar DLQ).
//! * grant/resolve order, ubah status member, rate-limit member,
//!   refund-record, rekonsiliasi keuangan -> support.
//! * paket/produk/pengaturan (rate-limit default, trial, provider
//!   guard, endpoint provider, tester), kunci API member
//!   (buat/cabut/reveal/regenerate), pengaturan QRIS, assign paket
//!   member (Fase 3, B20), export CSV (Fase 3, B23), replay DLQ
//!   (Fase 3, B26), site-settings -> manager.
//! * kelola admin (list/tambah/ubah peran/nonaktifkan/hapus) -> owner.
//!
//! Matriks peran Fase 3 (K40 — selaras ke sisi yang lebih ketat):
//! aturan dasarnya "semua GET = Viewer", dengan pengecualian
//! BERPOKOK yang didokumentasikan di sini, bukan diam-diam:
//! - Site-settings GET = Manager: bukan data operasional, melainkan
//!   konfigurasi situs (pengumuman, banner, sakelar blokir) — baca
//!   dan tulisnya satu paket.
//! - Daftar refund-record per order = Support, rekonsiliasi = Support:
//!   keduanya angka KEUANGAN (uang kembali / nominal per status),
//!   sekeluarga dengan pencatatan refund (Support) — sementara
//!   daftar/detail order biasa tetap Viewer (bacaan operasional).
//! - Detail member = Viewer, TETAPI field `google_sub` (pengenal
//!   login stabil) hanya diserialisasi untuk Manager+.
//! - Export CSV = Manager (B23): bacaan massal 10.000 baris termasuk
//!   email bukan "baca saja" biasa.
//! - Assign paket = Manager + cap kuota manual 10.000.000 (B20):
//!   memberi/menghapus kuota adalah mutasi keuangan, bukan dukungan
//!   pelanggan biasa.

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::AdminPrincipal, error::AppError, models::ActivityItem, store::AdminStore,
};


/// Peran admin, dari yang paling terbatas ke yang paling berkuasa.
/// Urutan varian BUKAN otoritas — pakai `rank()`, bukan discriminant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Support,
    Manager,
    Owner,
}

impl Role {
    /// Tingkat otoritas: viewer 0 < support 1 < manager 2 < owner 3.
    pub fn rank(self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Support => 1,
            Role::Manager => 2,
            Role::Owner => 3,
        }
    }

    /// Nama peran persis seperti yang disimpan di kolom `admins.role`.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Support => "support",
            Role::Manager => "manager",
            Role::Owner => "owner",
        }
    }

    /// Apakah peran ini memenuhi ambang `min_role` (inklusif).
    /// Pure — dipakai tes matriks peran tanpa database.
    pub fn satisfies(self, min_role: Role) -> bool {
        self.rank() >= min_role.rank()
    }
}

impl FromStr for Role {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "viewer" => Ok(Role::Viewer),
            "support" => Ok(Role::Support),
            "manager" => Ok(Role::Manager),
            "owner" => Ok(Role::Owner),
            _ => Err(()),
        }
    }
}

/// Satu baris tabel `admins` (migrasi 0019). `id` adalah UUID yang
/// dipakai endpoint kelola admin di path, agar email tidak perlu
/// di-URL-encode di path.
#[derive(Clone, Debug, Serialize)]
pub struct AdminAccount {
    pub id: Uuid,
    pub email: String,
    pub role: Role,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Option<String>,
}

/// Hasil resolusi peran. `fallback` true berarti sesi lolos cek lama
/// tetapi belum punya baris `admins` sehingga diperlakukan sebagai
/// owner (lihat header modul). Koordinator/panel boleh menampilkannya
/// sebagai penanda "peran belum diatur eksplisit".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedRole {
    pub role: Role,
    pub fallback: bool,
}

/// Normalisasi email admin: trim + lowercase, sama seperti
/// `parse_email_set` di config dan normalisasi di `auth.rs`.
pub fn normalize_admin_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Validasi email admin untuk endpoint tambah admin: bentuk minimal
/// (satu `@`, tanpa spasi, panjang wajar). Bukan validasi RFC penuh —
/// gerbang login (allowlist Google) tetap yang menentukan apakah
/// email ini benar-benar bisa masuk.
pub fn validate_admin_email(email: &str) -> Result<String, AppError> {
    let normalized = normalize_admin_email(email);
    let valid = !normalized.is_empty()
        && normalized.len() <= 255
        && !normalized.contains(char::is_whitespace)
        && normalized.matches('@').count() == 1
        && !normalized.starts_with('@')
        && !normalized.ends_with('@');
    if valid {
        Ok(normalized)
    } else {
        Err(AppError::bad_request("Email admin tidak valid"))
    }
}

/// Resolusi peran sebuah sesi admin yang sudah sah. Akun yang
/// dinonaktifkan ditolak (403) meski sesinya masih berlaku — owner
/// yang menonaktifkan tidak perlu menunggu sesi itu kedaluwarsa.
/// Akun yang DIHAPUS juga ditolak (403) sebelum fallback: tombstone
/// `deleted_admins` diperiksa dulu, jadi penghapusan persisten meski
/// sesi JWT lama masih berlaku. Sesi tanpa baris `admins` dan tanpa
/// tombstone jatuh ke fallback owner (lihat header).

pub async fn resolve_admin_role(
    store: &AdminStore,
    principal: &AdminPrincipal,
) -> Result<ResolvedRole, AppError> {
    let email = normalize_admin_email(&principal.email);
    match store.get_admin_account(&email).await {
        Some(account) => {
            if !account.active {
                return Err(AppError::forbidden(
                    "Akun admin ini dinonaktifkan. Hubungi owner.",
                ));
            }
            Ok(ResolvedRole {
                role: account.role,
                fallback: false,
            })
        }
        None => {
            // R1: penghapusan PERSISTEN diperiksa SEBELUM fallback.
            // Email di tombstone `deleted_admins` ditolak 403 seperti
            // akun dinonaktifkan — fallback owner TIDAK boleh
            // membangkitkannya, dan seed di bawah tidak dipanggil
            // untuknya. Cek ini hanya berjalan di cabang None (tanpa
            // baris), jadi demote/deactivate (baris tetap ada) dan
            // admin lama yang belum pernah dihapus tidak terpengaruh.
            if store.is_admin_deleted(&email).await? {
                return Err(AppError::forbidden(
                    "Akun admin ini telah dihapus. Hubungi owner.",
                ));
            }
            // Fallback anti-kunci: sesi ini SUDAH lolos cek lama
            // (allowlist/token/login lokal), jadi memperlakukannya
            // sebagai owner tidak membuka akses baru — hanya
            // mempertahankan akses lama sampai owner mengatur peran.
            store.seed_legacy_admin(&email).await;
            tracing::warn!(
                email = %email,
                "Admin lama tanpa baris admins diperlakukan sebagai owner (fallback seed)"
            );
            Ok(ResolvedRole {
                role: Role::Owner,
                fallback: true,
            })
        }

    }
}

/// Gerbang peran utama. Kembalikan peran teresolusi bila memenuhi
/// `min_role`; selain itu 403. Pesan menyebut peran yang dibutuhkan
/// tanpa membocorkan daftar admin.
/// Gerbang peran lama, dipertahankan apa adanya untuk pemanggil
/// read-only: penolakan dari jalur ini TIDAK menulis jejak audit.
/// Endpoint sensitif memakai `require_role_at` di bawah.
pub async fn require_role(
    store: &AdminStore,
    principal: &AdminPrincipal,
    min_role: Role,
) -> Result<Role, AppError> {
    require_role_at(store, principal, min_role, None).await
}

/// Jendela dedup jejak penolakan (K38): satu baris audit per
/// aktor+endpoint+peran yang dibutuhkan per 15 menit. Cukup untuk
/// forensik probing peran (Viewer menembak endpoint Manager berulang
/// kali tetap meninggalkan SATU baris per jendela) tanpa membanjiri
/// admin_audit_log bila satu aktor menembak tanpa henti.
const DENIAL_AUDIT_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Peta dedup proses-global: kunci "aktor|endpoint|peran" -> terakhir
/// dicatat. Entri basi dipangkas oportunistik tiap panggilan, jadi peta
/// terbatas pada kombinasi aktor x endpoint x peran yang aktif dalam
/// satu jendela — bukan tumbuh tanpa batas. Mutex poisoned -> audit
/// dilewati (fail-closed untuk jejak saja; 403 tetap dikembalikan).
static DENIAL_AUDIT_SEEN: OnceLock<Mutex<HashMap<String, Instant>>> =
    OnceLock::new();

/// Inti dedup yang bisa dites tanpa state global: true = baris audit
/// boleh ditulis (dan cap dicatat); false = masih dalam jendela.
fn denial_dedup_allows(
    seen: &mut HashMap<String, Instant>,
    key: &str,
    now: Instant,
    window: Duration,
) -> bool {
    seen.retain(|_, at| now.duration_since(*at) < window);
    if seen.contains_key(key) {
        return false;
    }
    seen.insert(key.to_owned(), now);
    true
}

fn denial_audit_allowed(key: &str) -> bool {
    let seen = DENIAL_AUDIT_SEEN.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut guard) = seen.lock() else {
        return false;
    };
    denial_dedup_allows(&mut guard, key, Instant::now(), DENIAL_AUDIT_WINDOW)
}

/// Detail baris penolakan: aktor, perannya, endpoint, peran yang
/// dibutuhkan. Tanpa nilai sensitif apa pun.
fn denial_audit_detail(
    actor: &str,
    actor_role: Role,
    endpoint: &str,
    required: Role,
) -> String {
    format!(
        "{} (peran {}) ditolak mengakses {}; butuh peran {} atau lebih tinggi.",
        actor,
        actor_role.as_str(),
        endpoint,
        required.as_str()
    )
}

/// Varian `require_role` untuk endpoint sensitif (K38). Bila peran
/// ditolak DAN endpoint terisi, satu baris audit ringan ditulis
/// (durable admin_audit_log + mirror in-memory, lewat jalur store yang
/// sama dengan audit sukses; gagal tulis tidak pernah menggagalkan
/// 403). Penulisan di-throttle oleh `denial_audit_allowed`.
/// `endpoint` = label route dari router (mis. "PATCH /v1/admin/...").
pub async fn require_role_at(
    store: &AdminStore,
    principal: &AdminPrincipal,
    min_role: Role,
    endpoint: Option<&str>,
) -> Result<Role, AppError> {
    let resolved = resolve_admin_role(store, principal).await?;
    if !resolved.role.satisfies(min_role) {
        if let Some(endpoint) = endpoint {
            let key = format!(
                "{}|{}|{}",
                principal.email,
                endpoint,
                min_role.as_str()
            );
            if denial_audit_allowed(&key) {
                let detail =
                    denial_audit_detail(&principal.email, resolved.role, endpoint, min_role);
                store
                    .persist_admin_audit(
                        &principal.email,
                        "Akses admin ditolak",
                        &detail,
                        None,
                        None,
                    )
                    .await;
                store
                    .append_activity(ActivityItem {
                        id: Uuid::now_v7(),
                        title: "Akses admin ditolak".to_owned(),
                        detail: format!("{} • oleh {}", detail, principal.email),
                        product: None,
                        status: "info".to_owned(),
                        occurred_at: chrono::Utc::now(),
                        provider_latency_ms: None,
                    })
                    .await;
            }
        }
        return Err(AppError::forbidden(format!(
            "Peran {} tidak memiliki akses ini (butuh peran {} atau lebih tinggi).",
            resolved.role.as_str(),
            min_role.as_str()
        )));
    }
    Ok(resolved.role)
}


#[cfg(test)]
mod role_tests {
    use super::*;

    #[test]
    fn role_ranks_form_a_strict_hierarchy() {
        assert!(Role::Viewer.rank() < Role::Support.rank());
        assert!(Role::Support.rank() < Role::Manager.rank());
        assert!(Role::Manager.rank() < Role::Owner.rank());
    }

    #[test]
    fn role_matrix_matches_the_spec() {
        // viewer ditolak menulis apa pun (butuh support ke atas).
        assert!(!Role::Viewer.satisfies(Role::Support));
        assert!(!Role::Viewer.satisfies(Role::Manager));
        assert!(!Role::Viewer.satisfies(Role::Owner));
        // support ditolak ubah paket/pengaturan (butuh manager).
        assert!(Role::Support.satisfies(Role::Support));
        assert!(!Role::Support.satisfies(Role::Manager));
        // manager ditolak kelola admin (butuh owner).
        assert!(Role::Manager.satisfies(Role::Manager));
        assert!(!Role::Manager.satisfies(Role::Owner));
        // owner lolos semua.
        assert!(Role::Owner.satisfies(Role::Viewer));
        assert!(Role::Owner.satisfies(Role::Support));
        assert!(Role::Owner.satisfies(Role::Manager));
        assert!(Role::Owner.satisfies(Role::Owner));
        // Ambang read-only: semua peran boleh membaca.
        for role in [Role::Viewer, Role::Support, Role::Manager, Role::Owner] {
            assert!(role.satisfies(Role::Viewer));
        }
    }

    #[test]
    fn denial_dedup_allows_once_per_window_per_key() {
        let window = Duration::from_secs(15 * 60);
        let mut seen = HashMap::new();
        let now = Instant::now();
        let key = "viewer@contoh.id|PATCH /v1/admin/products/:id|manager";
        // Percobaan pertama dicatat; pengulangan dalam jendela dibungkam.
        assert!(denial_dedup_allows(&mut seen, key, now, window));
        assert!(!denial_dedup_allows(&mut seen, key, now, window));
        assert!(!denial_dedup_allows(
            &mut seen,
            key,
            now + Duration::from_secs(60),
            window
        ));
        // Aktor/endpoint/peran berbeda tidak saling membungkam.
        assert!(denial_dedup_allows(
            &mut seen,
            "viewer@contoh.id|POST /v1/admin/api-keys|manager",
            now,
            window
        ));
        // Setelah jendela lewat, kunci yang sama boleh dicatat lagi
        // (dan entri basi sudah dipangkas oleh retain di atas).
        assert!(denial_dedup_allows(
            &mut seen,
            key,
            now + Duration::from_secs(15 * 60 + 1),
            window
        ));
    }

    #[test]
    fn denial_detail_names_actor_role_endpoint_and_required_role() {
        let detail = denial_audit_detail(
            "viewer@contoh.id",
            Role::Viewer,
            "PATCH /v1/admin/products/:id",
            Role::Manager,
        );
        assert!(detail.contains("viewer@contoh.id"), "{detail}");
        assert!(detail.contains("peran viewer"), "{detail}");
        assert!(detail.contains("PATCH /v1/admin/products/:id"), "{detail}");
        assert!(detail.contains("butuh peran manager"), "{detail}");
    }

    #[test]
    fn role_parsing_is_case_insensitive_and_strict() {

        assert_eq!("Viewer".parse::<Role>(), Ok(Role::Viewer));
        assert_eq!(" SUPPORT ".parse::<Role>(), Ok(Role::Support));
        assert_eq!("manager".parse::<Role>(), Ok(Role::Manager));
        assert_eq!("OWNER".parse::<Role>(), Ok(Role::Owner));
        assert!("admin".parse::<Role>().is_err());
        assert!("superuser".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
    }

    /// Seed/fallback: sesi admin yang lolos cek lama tetapi tanpa
    /// baris `admins` (di sini disimulasikan dengan store tanpa
    /// database, sehingga get selalu None) HARUS menjadi owner,
    /// bukan terkunci atau jatuh ke viewer.
    #[tokio::test]
    async fn legacy_admin_without_row_falls_back_to_owner() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let principal = AdminPrincipal {
            email: "lama@contoh.id".to_owned(),
            name: "Admin Lama".to_owned(),
            source: "google_session",
            jti: "fallback-test-jti".to_owned(),
        };
        let resolved = resolve_admin_role(&store, &principal)
            .await
            .expect("fallback owner");
        assert_eq!(resolved.role, Role::Owner);
        assert!(resolved.fallback);
        // Dan owner fallback lolos semua ambang, termasuk kelola admin.
        assert_eq!(
            require_role(&store, &principal, Role::Owner)
                .await
                .expect("owner lolos"),
            Role::Owner
        );
    }

    #[tokio::test]
    async fn fallback_owner_satisfies_every_threshold() {
        let store = AdminStore::new(None, 60).expect("store baru");
        let principal = AdminPrincipal {
            email: "admin@local.dev".to_owned(),
            name: "Administrator Lokal".to_owned(),
            source: "development_token",
            jti: String::new(),
        };
        for min in [Role::Viewer, Role::Support, Role::Manager, Role::Owner] {
            assert!(require_role(&store, &principal, min).await.is_ok());
        }
    }

    #[test]
    fn email_normalization_and_validation() {
        assert_eq!(
            normalize_admin_email("  Admin@Contoh.ID "),
            "admin@contoh.id"
        );
        assert!(validate_admin_email("admin@contoh.id").is_ok());
        assert!(validate_admin_email("tanpa-at").is_err());
        assert!(validate_admin_email("a@b@c").is_err());
        assert!(validate_admin_email("@contoh.id").is_err());
        assert!(validate_admin_email("admin@").is_err());
        assert!(validate_admin_email("admin @contoh.id").is_err());
    }

    // --- Tes R1 (tombstone penghapusan admin, migrasi 0028) ---
    // Helper: pool tes HANYA bila RAJACEK_TEST_DATABASE_URL diset dan
    // bisa dikonek; bila tidak, kembalikan None dan tes memanggil
    // langsung return (skip). Tidak pernah menyentuh database live
    // tanpa env eksplisit ini.
    async fn r1_test_pool() -> Option<sqlx::MySqlPool> {
        let url = std::env::var("RAJACEK_TEST_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        let pool = sqlx::MySqlPool::connect(&url).await.ok()?;
        // Skema minimal yang dipakai tes (salinan migrasi 0019 + 0028).
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS admins (
                id CHAR(36) NOT NULL PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                role VARCHAR(32) NOT NULL DEFAULT 'viewer',
                active TINYINT(1) NOT NULL DEFAULT 1,
                created_at DATETIME(6) NOT NULL,
                updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
                created_by VARCHAR(255) NULL,
                INDEX idx_admins_role (role),
                INDEX idx_admins_active (active)
            )",
        )
        .execute(&pool)
        .await;
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS deleted_admins (
                email VARCHAR(255) NOT NULL PRIMARY KEY,
                deleted_at DATETIME(6) NOT NULL,
                deleted_by VARCHAR(255) NULL,
                INDEX idx_deleted_admins_deleted_at (deleted_at)
            )",
        )
        .execute(&pool)
        .await;
        Some(pool)
    }

    async fn r1_store(pool: sqlx::MySqlPool) -> AdminStore {
        let store = AdminStore::new(None, 60).expect("store baru");
        store.attach_pool(pool);
        store
    }

    fn r1_principal(email: &str) -> AdminPrincipal {
        AdminPrincipal {
            email: email.to_owned(),
            name: "Tes R1".to_owned(),
            source: "google_session",
            jti: "r1-test-jti".to_owned(),
        }
    }

    fn r1_email(tag: &str) -> String {
        format!("r1-{tag}-{}@contoh.test", Uuid::now_v7())
    }

    async fn r1_assert_forbidden(store: &AdminStore, email: &str) {
        let err = resolve_admin_role(store, &r1_principal(email))
            .await
            .expect_err("admin terhapus/dinonaktifkan harus ditolak");
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }

    /// Syarat 1: hapus -> login ulang (resolve, termasuk sesi JWT lama
    /// yang masih berlaku) -> 403, dan seed malas tidak membangkitkan.
    #[tokio::test]
    async fn r1_deleted_admin_rejected_after_lazy_fallback_and_seed() {
        let Some(pool) = r1_test_pool().await else {
            return;
        };
        let store = r1_store(pool).await;
        let email = r1_email("hapus");
        let account = store
            .create_admin_account(&email, Role::Viewer, "owner-tes")
            .await
            .expect("buat admin");
        assert!(store
            .delete_admin_account(account.id, "owner-tes")
            .await
            .expect("hapus admin"));
        assert!(store.is_admin_deleted(&email).await.unwrap());
        assert!(store.get_admin_account(&email).await.is_none());
        // Login ulang: bukan fallback Owner, melainkan 403.
        r1_assert_forbidden(&store, &email).await;
        // Seed malas per-request TIDAK boleh menulis baris baru.
        store.seed_legacy_admin(&email).await;
        assert!(store.get_admin_account(&email).await.is_none());
        r1_assert_forbidden(&store, &email).await;
        // Daftar admin tidak lagi memuatnya (baris memang terhapus,
        // bukan soft-delete — tidak ada filter daftar yang diperlukan).
        assert!(!store
            .list_admin_accounts()
            .await
            .iter()
            .any(|item| item.email == email));
    }

    /// Syarat 2: hapus -> restart (seed startup = seed_legacy_admins
    /// atas seluruh allowlist) -> tetap 403, tanpa baris baru.
    #[tokio::test]
    async fn r1_deleted_admin_survives_startup_seed() {
        let Some(pool) = r1_test_pool().await else {
            return;
        };
        let store = r1_store(pool).await;
        let email = r1_email("restart");
        let account = store
            .create_admin_account(&email, Role::Viewer, "owner-tes")
            .await
            .expect("buat admin");
        assert!(store
            .delete_admin_account(account.id, "owner-tes")
            .await
            .expect("hapus admin"));
        // Simulasi seed startup main.rs atas allowlist yang masih
        // memuat email ini.
        store.seed_legacy_admins(&[email.clone()]).await;
        assert!(store.get_admin_account(&email).await.is_none());
        assert!(store.is_admin_deleted(&email).await.unwrap());
        r1_assert_forbidden(&store, &email).await;
    }

    /// Syarat 3: email allowlist baru yang belum pernah punya baris
    /// dan belum pernah dihapus TETAP mendapat fallback Owner.
    #[tokio::test]
    async fn r1_never_seen_allowlist_email_still_falls_back_to_owner() {
        let Some(pool) = r1_test_pool().await else {
            return;
        };
        let store = r1_store(pool).await;
        let email = r1_email("baru");
        assert!(!store.is_admin_deleted(&email).await.unwrap());
        let resolved = resolve_admin_role(&store, &r1_principal(&email))
            .await
            .expect("fallback owner untuk admin lama");
        assert_eq!(resolved.role, Role::Owner);
        assert!(resolved.fallback);
        // Seed malas telah menulis baris owner: resolusi kedua bukan
        // lagi fallback, tetapi tetap owner (kompatibilitas terjaga).
        let resolved = resolve_admin_role(&store, &r1_principal(&email))
            .await
            .expect("owner hasil seed");
        assert_eq!(resolved.role, Role::Owner);
        assert!(!resolved.fallback);
    }

    /// Syarat 4: demote dan deactivate tidak berubah — baris tetap ada
    /// (bukan tombstone), seed tidak mengaktifkan ulang, dan pesan
    /// penolakan deactivate tetap 403 seperti sebelumnya.
    #[tokio::test]
    async fn r1_demote_and_deactivate_unchanged() {
        let Some(pool) = r1_test_pool().await else {
            return;
        };
        let store = r1_store(pool).await;
        let email = r1_email("demote");
        let account = store
            .create_admin_account(&email, Role::Manager, "owner-tes")
            .await
            .expect("buat admin");
        // Demote: peran berubah, resolve mengikuti baris (bukan tombstone).
        let updated = store
            .update_admin_account(account.id, Some(Role::Viewer), None)
            .await
            .expect("demote")
            .expect("baris demote ada");
        assert_eq!(updated.role, Role::Viewer);
        assert!(!store.is_admin_deleted(&email).await.unwrap());
        let resolved = resolve_admin_role(&store, &r1_principal(&email))
            .await
            .expect("viewer hasil demote");
        assert_eq!(resolved.role, Role::Viewer);
        assert!(!resolved.fallback);
        // Deactivate: resolve 403, tetapi baris TETAP ada di daftar.
        store
            .update_admin_account(account.id, None, Some(false))
            .await
            .expect("deactivate")
            .expect("baris deactivate ada");
        r1_assert_forbidden(&store, &email).await;
        assert!(!store.is_admin_deleted(&email).await.unwrap());
        assert!(store
            .list_admin_accounts()
            .await
            .iter()
            .any(|item| item.email == email));
        // Seed tidak mengaktifkan ulang akun yang dinonaktifkan
        // (INSERT IGNORE tidak menimpa baris yang sudah ada).
        store.seed_legacy_admin(&email).await;
        let current = store.get_admin_account(&email).await.expect("baris ada");
        assert!(!current.active);
    }

    /// Revive eksplisit: membuat ulang email yang dihapus lewat
    /// endpoint tambah admin membersihkan tombstone dan resolve
    /// kembali lolos dengan peran baru.
    #[tokio::test]
    async fn r1_recreated_admin_clears_tombstone() {
        let Some(pool) = r1_test_pool().await else {
            return;
        };
        let store = r1_store(pool).await;
        let email = r1_email("buat-ulang");
        let account = store
            .create_admin_account(&email, Role::Viewer, "owner-tes")
            .await
            .expect("buat admin");
        assert!(store
            .delete_admin_account(account.id, "owner-tes")
            .await
            .expect("hapus admin"));
        assert!(store.is_admin_deleted(&email).await.unwrap());
        store
            .create_admin_account(&email, Role::Support, "owner-tes")
            .await
            .expect("buat ulang admin");
        assert!(!store.is_admin_deleted(&email).await.unwrap());
        let resolved = resolve_admin_role(&store, &r1_principal(&email))
            .await
            .expect("admin dibuat ulang lolos");
        assert_eq!(resolved.role, Role::Support);
        assert!(!resolved.fallback);
    }
}

