use std::collections::{HashMap, HashSet};

use foldhash::fast::RandomState;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Metadata for a preset blocked service exposed to the API and Web UI.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlockedServiceInfo {
    pub id: String,
    pub name: String,
    pub category: String,
    pub domain_count: usize,
}

/// Global preset blocked-services configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BlockedServicesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub services: Vec<String>,
}

struct ServiceDef {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    domains: &'static [&'static str],
}

const SERVICE_CATALOG: &[ServiceDef] = &[
    ServiceDef {
        id: "youtube",
        name: "YouTube",
        category: "video",
        domains: &[
            "youtube.com",
            "youtu.be",
            "ytimg.com",
            "googlevideo.com",
            "youtube-nocookie.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "yt3.ggpht.com",
        ],
    },
    ServiceDef {
        id: "netflix",
        name: "Netflix",
        category: "video",
        domains: &[
            "netflix.com",
            "netflix.net",
            "nflxvideo.net",
            "nflximg.net",
            "nflxso.net",
            "nflxext.com",
        ],
    },
    ServiceDef {
        id: "twitch",
        name: "Twitch",
        category: "video",
        domains: &["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net"],
    },
    ServiceDef {
        id: "bilibili",
        name: "Bilibili",
        category: "video",
        domains: &[
            "bilibili.com",
            "biliapi.net",
            "biliapi.com",
            "bilivideo.com",
            "hdslb.com",
            "b23.tv",
        ],
    },
    ServiceDef {
        id: "douyin",
        name: "Douyin",
        category: "video",
        domains: &[
            "douyin.com",
            "douyincdn.com",
            "douyinvod.com",
            "iesdouyin.com",
            "amemv.com",
        ],
    },
    ServiceDef {
        id: "iqiyi",
        name: "iQIYI",
        category: "video",
        domains: &["iqiyi.com", "iqiyipic.com", "qiyi.com", "qy.net"],
    },
    ServiceDef {
        id: "spotify",
        name: "Spotify",
        category: "video",
        domains: &["spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"],
    },
    ServiceDef {
        id: "tiktok",
        name: "TikTok",
        category: "social",
        domains: &[
            "tiktok.com",
            "tiktokcdn.com",
            "tiktokcdn-us.com",
            "tiktokv.com",
            "musical.ly",
            "byteoversea.com",
        ],
    },
    ServiceDef {
        id: "facebook",
        name: "Facebook",
        category: "social",
        domains: &[
            "facebook.com",
            "fb.com",
            "fbcdn.net",
            "fbsbx.com",
            "messenger.com",
        ],
    },
    ServiceDef {
        id: "instagram",
        name: "Instagram",
        category: "social",
        domains: &["instagram.com", "cdninstagram.com"],
    },
    ServiceDef {
        id: "twitter",
        name: "X (Twitter)",
        category: "social",
        domains: &["twitter.com", "x.com", "twimg.com", "t.co"],
    },
    ServiceDef {
        id: "reddit",
        name: "Reddit",
        category: "social",
        domains: &[
            "reddit.com",
            "redd.it",
            "redditmedia.com",
            "redditstatic.com",
        ],
    },
    ServiceDef {
        id: "snapchat",
        name: "Snapchat",
        category: "social",
        domains: &["snapchat.com", "sc-cdn.net", "snap-dev.net", "snapkit.co"],
    },
    ServiceDef {
        id: "discord",
        name: "Discord",
        category: "social",
        domains: &[
            "discord.com",
            "discordapp.com",
            "discordapp.net",
            "discord.gg",
            "discord.media",
        ],
    },
    ServiceDef {
        id: "telegram",
        name: "Telegram",
        category: "social",
        domains: &["telegram.org", "t.me", "telegra.ph", "tdesktop.com"],
    },
    ServiceDef {
        id: "whatsapp",
        name: "WhatsApp",
        category: "social",
        domains: &["whatsapp.com", "whatsapp.net", "wa.me"],
    },
    ServiceDef {
        id: "wechat",
        name: "WeChat",
        category: "social",
        domains: &[
            "wechat.com",
            "weixin.qq.com",
            "wx.qq.com",
            "servicewechat.com",
        ],
    },
    ServiceDef {
        id: "weibo",
        name: "Weibo",
        category: "social",
        domains: &["weibo.com", "weibo.cn", "weibocdn.com", "sinaimg.cn"],
    },
    ServiceDef {
        id: "xiaohongshu",
        name: "Xiaohongshu",
        category: "social",
        domains: &["xiaohongshu.com", "xhscdn.com", "xhslink.com"],
    },
    ServiceDef {
        id: "steam",
        name: "Steam",
        category: "gaming",
        domains: &[
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcontent.com",
            "steamgames.com",
            "steam-chat.com",
        ],
    },
    ServiceDef {
        id: "epic_games",
        name: "Epic Games",
        category: "gaming",
        domains: &["epicgames.com", "unrealengine.com", "fortnite.com"],
    },
    ServiceDef {
        id: "roblox",
        name: "Roblox",
        category: "gaming",
        domains: &["roblox.com", "rbxcdn.com", "rbx.com"],
    },
    ServiceDef {
        id: "playstation",
        name: "PlayStation",
        category: "gaming",
        domains: &[
            "playstation.com",
            "playstation.net",
            "sonyentertainmentnetwork.com",
        ],
    },
    ServiceDef {
        id: "xbox",
        name: "Xbox Live",
        category: "gaming",
        domains: &["xbox.com", "xboxlive.com", "xboxab.com"],
    },
    ServiceDef {
        id: "nintendo",
        name: "Nintendo",
        category: "gaming",
        domains: &["nintendo.com", "nintendo.net", "nintendo.co.jp"],
    },
    ServiceDef {
        id: "riot_games",
        name: "Riot Games",
        category: "gaming",
        domains: &[
            "riotgames.com",
            "leagueoflegends.com",
            "playvalorant.com",
            "riotcdn.net",
        ],
    },
    ServiceDef {
        id: "openai",
        name: "OpenAI / ChatGPT",
        category: "ai",
        domains: &[
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
        ],
    },
    ServiceDef {
        id: "claude",
        name: "Claude",
        category: "ai",
        domains: &["anthropic.com", "claude.ai"],
    },
    ServiceDef {
        id: "amazon",
        name: "Amazon",
        category: "shopping",
        domains: &[
            "amazon.com",
            "amazon.co.uk",
            "amazon.de",
            "amazon.co.jp",
            "media-amazon.com",
        ],
    },
    ServiceDef {
        id: "taobao",
        name: "Taobao / Tmall",
        category: "shopping",
        domains: &["taobao.com", "tmall.com", "alicdn.com", "tbcdn.cn"],
    },
    ServiceDef {
        id: "jd",
        name: "JD.com",
        category: "shopping",
        domains: &["jd.com", "360buyimg.com", "jd.hk"],
    },
    ServiceDef {
        id: "pinduoduo",
        name: "Pinduoduo",
        category: "shopping",
        domains: &["pinduoduo.com", "yangkeduo.com", "pddpic.com"],
    },
];

/// Compiled lookup index for preset blocked services.
#[derive(Debug, Clone)]
pub struct BlockedServicesMatcher {
    config: BlockedServicesConfig,
    global_ids: HashSet<String, RandomState>,
    domain_to_service: HashMap<&'static str, &'static str, RandomState>,
}

impl Default for BlockedServicesMatcher {
    fn default() -> Self {
        Self::new(BlockedServicesConfig::default())
    }
}

impl BlockedServicesMatcher {
    /// Builds a matcher from the given global [`BlockedServicesConfig`].
    pub fn new(config: BlockedServicesConfig) -> Self {
        let valid_ids: HashSet<&'static str, RandomState> =
            SERVICE_CATALOG.iter().map(|s| s.id).collect();
        let global_ids: HashSet<String, RandomState> = if config.enabled {
            config
                .services
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| valid_ids.contains(s.as_str()))
                .collect()
        } else {
            HashSet::with_hasher(RandomState::default())
        };

        let mut domain_to_service = HashMap::with_hasher(RandomState::default());
        for svc in SERVICE_CATALOG {
            for &dom in svc.domains {
                domain_to_service.insert(dom, svc.id);
            }
        }

        Self {
            config,
            global_ids,
            domain_to_service,
        }
    }

    pub fn config(&self) -> &BlockedServicesConfig {
        &self.config
    }

    /// Returns `Some(service_id)` if `domain` belongs to a service blocked for this query.
    ///
    /// When `client_override` is `Some(list)`, it replaces the global blocked-services list
    /// (so `Some(&[])` explicitly allows all preset services for that client).
    pub fn match_domain(
        &self,
        domain: &str,
        client_override: Option<&[String]>,
    ) -> Option<&'static str> {
        let has_override = client_override.is_some();
        if !has_override && self.global_ids.is_empty() {
            return None;
        }
        if let Some(list) = client_override
            && list.is_empty()
        {
            return None;
        }

        let norm = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            return None;
        }

        let mut candidate = norm.as_str();
        loop {
            if let Some(&svc_id) = self.domain_to_service.get(candidate) {
                let active = match client_override {
                    Some(list) => list.iter().any(|s| s.eq_ignore_ascii_case(svc_id)),
                    None => self.global_ids.contains(svc_id),
                };
                if active {
                    return Some(svc_id);
                }
            }
            match candidate.split_once('.') {
                Some((_, rest)) => candidate = rest,
                None => break,
            }
        }
        None
    }
}

/// Returns metadata for all built-in preset services.
pub fn list_blocked_services() -> Vec<BlockedServiceInfo> {
    SERVICE_CATALOG
        .iter()
        .map(|s| BlockedServiceInfo {
            id: s.id.to_string(),
            name: s.name.to_string(),
            category: s.category.to_string(),
            domain_count: s.domains.len(),
        })
        .collect()
}

/// Normalizes and filters a list of service IDs to known catalog entries (deduplicated).
pub fn normalize_service_ids(ids: &[String]) -> Vec<String> {
    let valid_ids: HashSet<&'static str, RandomState> =
        SERVICE_CATALOG.iter().map(|s| s.id).collect();
    let mut seen = HashSet::with_hasher(RandomState::default());
    let mut out = Vec::new();
    for raw in ids {
        let norm = raw.trim().to_ascii_lowercase();
        if valid_ids.contains(norm.as_str()) && seen.insert(norm.clone()) {
            out.push(norm);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_services_global_and_subdomain() {
        let matcher = BlockedServicesMatcher::new(BlockedServicesConfig {
            enabled: true,
            services: vec!["tiktok".to_string(), "unknown_svc".to_string()],
        });
        assert_eq!(matcher.match_domain("tiktok.com", None), Some("tiktok"));
        assert_eq!(
            matcher.match_domain("api.tiktokv.com.", None),
            Some("tiktok")
        );
        assert_eq!(matcher.match_domain("youtube.com", None), None);
        assert_eq!(matcher.match_domain("nottiktok.com", None), None);
    }

    #[test]
    fn test_blocked_services_client_override() {
        let matcher = BlockedServicesMatcher::new(BlockedServicesConfig {
            enabled: true,
            services: vec!["youtube".to_string()],
        });
        assert_eq!(
            matcher.match_domain("www.youtube.com", None),
            Some("youtube")
        );
        // Client explicitly overrides with empty list -> allows YouTube.
        assert_eq!(matcher.match_domain("www.youtube.com", Some(&[])), None);
        // Client overrides with discord only -> blocks discord, allows youtube.
        let override_list = vec!["discord".to_string()];
        assert_eq!(
            matcher.match_domain("www.youtube.com", Some(&override_list)),
            None
        );
        assert_eq!(
            matcher.match_domain("cdn.discord.com", Some(&override_list)),
            Some("discord")
        );
    }

    #[test]
    fn test_normalize_service_ids() {
        let normalized = normalize_service_ids(&[
            " YouTube ".to_string(),
            "youtube".to_string(),
            "invalid".to_string(),
            "STEAM".to_string(),
        ]);
        assert_eq!(normalized, vec!["youtube", "steam"]);
    }
}
