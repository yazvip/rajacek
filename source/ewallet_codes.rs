use crate::error::AppError;

/// Stable public slugs translated to Tukangcek's provider-specific e-wallet IDs.
/// These IDs are only sent for endpoints configured with Tukangcek request mode.
const TUKANGCEK_IDS: &[(&str, &str)] = &[
    ("dana", "DANA001"),
    ("astrapay", "ASTRAPAY001"),
    ("gopay", "GOPAY001"),
    ("gopay_driver", "GOPAY002"),
    ("isaku", "ISAKU001"),
    ("kaspro", "KASPRO001"),
    ("linkaja", "LINKAJA001"),
    ("ovo", "OVO001"),
    ("shopeepay", "SHOPEEPAY001"),
];

/// Public e-wallet slugs with display names, for portal/admin dropdowns.
pub fn list() -> &'static [(&'static str, &'static str)] {
    &[
        ("dana", "DANA"),
        ("gopay", "GoPay"),
        ("ovo", "OVO"),
        ("linkaja", "LinkAja"),
        ("shopeepay", "ShopeePay"),
        ("astrapay", "AstraPay"),
        ("gopay_driver", "GoPay Driver"),
        ("isaku", "i.Saku"),
        ("kaspro", "KasPro"),
    ]
}

pub fn tukangcek_id(public_code: &str) -> Result<&'static str, AppError> {
    TUKANGCEK_IDS
        .iter()
        .find(|(code, _)| *code == public_code)
        .map(|(_, id)| *id)
        .ok_or_else(|| AppError::bad_request("Kode e-wallet tidak didukung"))
}

#[cfg(test)]
mod tests {
    use super::{tukangcek_id, TUKANGCEK_IDS};
    use std::collections::HashSet;

    #[test]
    fn every_supported_slug_has_a_unique_provider_id() {
        let expected = [
            ("dana", "DANA001"),
            ("astrapay", "ASTRAPAY001"),
            ("gopay", "GOPAY001"),
            ("gopay_driver", "GOPAY002"),
            ("isaku", "ISAKU001"),
            ("kaspro", "KASPRO001"),
            ("linkaja", "LINKAJA001"),
            ("ovo", "OVO001"),
            ("shopeepay", "SHOPEEPAY001"),
        ];
        assert_eq!(TUKANGCEK_IDS, expected);
        assert_eq!(
            TUKANGCEK_IDS
                .iter()
                .map(|(code, _)| code)
                .collect::<HashSet<_>>()
                .len(),
            9
        );
        assert_eq!(
            TUKANGCEK_IDS
                .iter()
                .map(|(_, id)| id)
                .collect::<HashSet<_>>()
                .len(),
            9
        );
        for (code, id) in expected {
            assert_eq!(tukangcek_id(code).expect("configured ID"), id);
        }
    }

    #[test]
    fn unknown_code_is_not_forwarded_to_provider() {
        assert!(tukangcek_id("unknown").is_err());
        assert!(tukangcek_id("GOPAY001").is_err());
    }
}
