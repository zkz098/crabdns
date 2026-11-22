use serde::{Deserialize, Serialize};
use ts_rs::TS;

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
#[allow(clippy::struct_excessive_bools)]
pub struct SafeSearchConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub google: bool,
    #[serde(default = "default_true")]
    pub bing: bool,
    #[serde(default = "default_true")]
    pub youtube: bool,
    #[serde(default)]
    pub youtube_strict: bool,
    #[serde(default = "default_true")]
    pub duckduckgo: bool,
    #[serde(default = "default_true")]
    pub yandex: bool,
    #[serde(default = "default_true")]
    pub pixabay: bool,
    #[serde(default = "default_true")]
    pub brave: bool,
}

impl Default for SafeSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            google: true,
            bing: true,
            youtube: true,
            youtube_strict: false,
            duckduckgo: true,
            yandex: true,
            pixabay: true,
            brave: true,
        }
    }
}

/// Returns `(engine_name, cname_target)` if `domain` should be rewritten for `SafeSearch`.
pub fn match_safesearch(
    config: &SafeSearchConfig,
    domain: &str,
    client_override: Option<bool>,
) -> Option<(&'static str, &'static str)> {
    let active = client_override.unwrap_or(config.enabled);
    if !active {
        return None;
    }

    let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() {
        return None;
    }

    if config.google && is_google_search_domain(&norm) {
        return Some(("google", "forcesafesearch.google.com"));
    }
    if config.bing && matches!(norm.as_str(), "bing.com" | "www.bing.com") {
        return Some(("bing", "strict.bing.com"));
    }
    if config.youtube && is_youtube_domain(&norm) {
        let target = if config.youtube_strict {
            "restrict.youtube.com"
        } else {
            "restrictmoderate.youtube.com"
        };
        return Some(("youtube", target));
    }
    if config.duckduckgo
        && matches!(
            norm.as_str(),
            "duckduckgo.com" | "www.duckduckgo.com" | "start.duckduckgo.com"
        )
    {
        return Some(("duckduckgo", "safe.duckduckgo.com"));
    }
    if config.yandex && is_yandex_search_domain(&norm) {
        return Some(("yandex", "familysearch.yandex.com"));
    }
    if config.pixabay && matches!(norm.as_str(), "pixabay.com" | "www.pixabay.com") {
        return Some(("pixabay", "safesearch.pixabay.com"));
    }
    if config.brave && norm == "search.brave.com" {
        return Some(("brave", "safesearch.search.brave.com"));
    }

    None
}

fn is_youtube_domain(norm: &str) -> bool {
    matches!(
        norm,
        "www.youtube.com"
            | "m.youtube.com"
            | "youtubei.googleapis.com"
            | "youtube.googleapis.com"
            | "www.youtube-nocookie.com"
    )
}

fn is_google_search_domain(norm: &str) -> bool {
    let bare = norm.strip_prefix("www.").unwrap_or(norm);
    let Some(tld) = bare.strip_prefix("google.") else {
        return false;
    };
    is_valid_search_tld(tld)
}

fn is_yandex_search_domain(norm: &str) -> bool {
    let bare = norm.strip_prefix("www.").unwrap_or(norm);
    let Some(tld) = bare.strip_prefix("yandex.") else {
        return false;
    };
    matches!(
        tld,
        "com" | "ru" | "by" | "kz" | "uz" | "com.tr" | "ee" | "lv" | "lt"
    )
}

fn is_valid_search_tld(tld: &str) -> bool {
    if tld == "com" || tld == "cat" {
        return true;
    }
    if tld.len() == 2 && tld.bytes().all(|b| b.is_ascii_lowercase()) {
        return true;
    }
    if let Some(cc) = tld.strip_prefix("com.").or_else(|| tld.strip_prefix("co.")) {
        return cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_lowercase());
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safesearch_disabled_and_client_override() {
        let cfg = SafeSearchConfig::default();
        assert_eq!(match_safesearch(&cfg, "www.google.com", None), None);
        assert_eq!(
            match_safesearch(&cfg, "www.google.com", Some(true)),
            Some(("google", "forcesafesearch.google.com"))
        );

        let enabled_cfg = SafeSearchConfig {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(
            match_safesearch(&enabled_cfg, "www.google.com", Some(false)),
            None
        );
    }

    #[test]
    fn test_safesearch_engines() {
        let cfg = SafeSearchConfig {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(
            match_safesearch(&cfg, "google.co.jp.", None),
            Some(("google", "forcesafesearch.google.com"))
        );
        assert_eq!(
            match_safesearch(&cfg, "www.google.com.hk", None),
            Some(("google", "forcesafesearch.google.com"))
        );
        assert_eq!(match_safesearch(&cfg, "mail.google.com", None), None);
        assert_eq!(
            match_safesearch(&cfg, "www.bing.com", None),
            Some(("bing", "strict.bing.com"))
        );
        assert_eq!(
            match_safesearch(&cfg, "www.youtube.com", None),
            Some(("youtube", "restrictmoderate.youtube.com"))
        );
        assert_eq!(
            match_safesearch(&cfg, "duckduckgo.com", None),
            Some(("duckduckgo", "safe.duckduckgo.com"))
        );
        assert_eq!(
            match_safesearch(&cfg, "yandex.ru", None),
            Some(("yandex", "familysearch.yandex.com"))
        );
        assert_eq!(
            match_safesearch(&cfg, "pixabay.com", None),
            Some(("pixabay", "safesearch.pixabay.com"))
        );
        assert_eq!(
            match_safesearch(&cfg, "search.brave.com", None),
            Some(("brave", "safesearch.search.brave.com"))
        );

        let strict_cfg = SafeSearchConfig {
            youtube_strict: true,
            ..cfg
        };
        assert_eq!(
            match_safesearch(&strict_cfg, "m.youtube.com", None),
            Some(("youtube", "restrict.youtube.com"))
        );
    }
}
