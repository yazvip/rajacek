use std::{collections::HashSet, sync::OnceLock};

use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BankCode {
    pub code_bank: String,
    pub name_bank: String,
    pub tukangcek_code: Option<String>,
}

/// Public catalog view: the upstream provider's institution codes are an
/// internal mapping detail and are never exposed to members.
#[derive(Serialize)]
pub struct PublicBankCode {
    pub code_bank: String,
    pub name_bank: String,
}

pub fn public_list() -> Vec<PublicBankCode> {
    list()
        .iter()
        .map(|bank| PublicBankCode {
            code_bank: bank.code_bank.clone(),
            name_bank: bank.name_bank.clone(),
        })
        .collect()
}

#[derive(Deserialize)]
struct BankCatalog {
    banks: Vec<BankCode>,
}

static CATALOG: OnceLock<Vec<BankCode>> = OnceLock::new();

pub fn list() -> &'static [BankCode] {
    CATALOG
        .get_or_init(|| {
            let mut catalog: BankCatalog =
                serde_json::from_str(include_str!("../data/bank_codes.json"))
                    .expect("data/bank_codes.json harus berupa JSON yang valid");
            catalog.banks.sort_by(|left, right| {
                left.code_bank
                    .cmp(&right.code_bank)
                    .then(left.name_bank.cmp(&right.name_bank))
            });
            catalog.banks
        })
        .as_slice()
}

pub fn bank_name(public_code: &str) -> Option<String> {
    list()
        .iter()
        .find(|bank| bank.code_bank == public_code)
        .map(|bank| bank.name_bank.clone())
}

pub fn validate_public_code(code: &str) -> Result<(), AppError> {
    let matches = list()
        .iter()
        .filter(|bank| bank.code_bank == code)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(AppError::bad_request(
            "Kode bank tidak ditemukan dalam katalog BANK_CODE Rajacek",
        ));
    }
    let names = matches
        .iter()
        .map(|bank| bank.name_bank.to_ascii_uppercase())
        .collect::<HashSet<_>>();
    if names.len() > 1 {
        tracing::warn!(code, banks = ?names, "Kode bank memiliki lebih dari satu varian nama");
    }
    Ok(())
}

pub fn tukangcek_code(public_code: &str) -> Result<&'static str, AppError> {
    let matches = list()
        .iter()
        .filter(|bank| bank.code_bank == public_code)
        .collect::<Vec<_>>();
    let configured = matches
        .iter()
        .filter_map(|bank| bank.tukangcek_code.as_deref())
        .collect::<HashSet<_>>();
    match configured.len() {
        1 => Ok(configured
            .into_iter()
            .next()
            .expect("satu mapping tersedia")),
        0 => Err(AppError::service_unavailable(format!(
            "Mapping kode bank {public_code} belum tersedia"
        ))),
        _ => Err(AppError::internal(format!(
            "Mapping kode bank {public_code} tidak valid"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{list, tukangcek_code};

    #[test]
    fn catalog_contains_confirmed_bri_translation() {
        assert!(list()
            .iter()
            .any(|bank| bank.code_bank == "002" && bank.name_bank == "BRI"));
        assert_eq!(tukangcek_code("002").expect("BRI mapped"), "BRIC1ID");
    }

    #[test]
    fn major_banks_translate_to_tukangcek_ids() {
        // Kode publik selalu 3 digit; ID yang dikirim ke Tukangcek adalah instId.
        assert_eq!(tukangcek_code("014").expect("BCA mapped"), "BCAC1ID");
        assert_eq!(tukangcek_code("008").expect("Mandiri mapped"), "MDRIC1ID");
        assert_eq!(tukangcek_code("009").expect("BNI mapped"), "BNIC1ID");
        assert_eq!(tukangcek_code("200").expect("BTN mapped"), "BTNUSC1ID");
        assert_eq!(tukangcek_code("490").expect("Neo mapped"), "BBYBC1ID");
    }

    #[test]
    fn every_catalog_code_resolves_to_exactly_one_tukangcek_id() {
        let mut per_code: HashMap<&str, &str> = HashMap::new();
        for bank in list() {
            assert_eq!(bank.code_bank.len(), 3, "kode publik harus 3 digit");
            assert!(bank.code_bank.chars().all(|c| c.is_ascii_digit()));
            let mapped = bank
                .tukangcek_code
                .as_deref()
                .expect("setiap baris katalog wajib memiliki mapping Tukangcek");
            match per_code.get(bank.code_bank.as_str()) {
                Some(existing) => assert_eq!(
                    *existing, mapped,
                    "kode {} memiliki mapping ambigu",
                    bank.code_bank
                ),
                None => {
                    per_code.insert(bank.code_bank.as_str(), mapped);
                }
            }
            assert_eq!(
                tukangcek_code(&bank.code_bank).expect("kode katalog harus dapat diterjemahkan"),
                mapped
            );
        }
        assert!(
            per_code.len() >= 111,
            "katalog menyusut: hanya {} kode unik",
            per_code.len()
        );
    }

    #[test]
    fn unknown_bank_code_is_rejected() {
        assert!(tukangcek_code("999").is_err());
        assert!(tukangcek_code("14").is_err());
    }
}
