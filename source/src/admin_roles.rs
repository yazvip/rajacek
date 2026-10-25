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
//!    terkunci — bahkan bila migrasi 0019 belum jalan, seed startup
//!    terlewat, atau barisnya terhapus — selama sesinya lolos cek lama.
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
//! * GET/read-only -> viewer (termasuk GET /v1/admin/activity).
//! * grant/resolve order, ubah status member, assign paket member,
//!   rate-limit member -> support.
//! * paket/produk/pengaturan (rate-limit default, trial, provider
//!   guard, endpoint provider, tester), kunci API member
//!   (buat/cabut/reveal/regenerate), pengaturan QRIS -> manager.
//! * kelola admin (list/tambah/ubah peran/nonaktifkan/hapus) -> owner.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::AdminPrincipal, error::AppError, store::AdminStore};

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
/// Sesi tanpa baris `admins` jatuh ke fallback owner (lihat header).
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
pub async fn require_role(
    store: &AdminStore,
    principal: &AdminPrincipal,
    min_role: Role,
) -> Result<Role, AppError> {
    let resolved = resolve_admin_role(store, principal).await?;
    if !resolved.role.satisfies(min_role) {
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
}
