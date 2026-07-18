//! Per-model token pricing and provider usage accounting.
//!
//! The proxy sits between the agent and the LLM provider, so it can read the
//! authoritative token counts the provider itself reports (`usage` in the
//! response) instead of guessing from byte volume. This module knows which
//! hosts are LLM providers, how to pull `usage` out of both buffered JSON and
//! SSE streams, what each model costs per million tokens, and whether a
//! request is billed per token at all: traffic authenticated with a
//! subscription (e.g. Claude Code signed into a Claude plan via OAuth) has
//! zero marginal cost and is recorded as such.
//!
//! Built-in rates are a snapshot; `pricing.json` in the state dir overrides
//! or extends hosts, model rates, and billing, and hot-reloads like policy.

use serde::Deserialize;
use std::collections::BTreeMap;

use crate::config;

/// USD per million tokens, split the way providers bill.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct ModelRate {
    pub input: f64,
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
    #[serde(default)]
    pub cache_write: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
    OpenAi,
}

impl Provider {
    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "anthropic" => Some(Provider::Anthropic),
            "openai" => Some(Provider::OpenAi),
            _ => None,
        }
    }

    /// Rate used when no model prefix matches: mid-tier for the provider, so
    /// an unlisted model is still priced rather than silently costing $0.
    fn default_rate(self) -> ModelRate {
        match self {
            Provider::Anthropic => ModelRate {
                input: 3.0,
                output: 15.0,
                cache_read: 0.3,
                cache_write: 3.75,
            },
            Provider::OpenAi => ModelRate {
                input: 2.5,
                output: 10.0,
                cache_read: 1.25,
                cache_write: 0.0,
            },
        }
    }
}

/// Whether a request's tokens are billed per use or covered by a flat plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Billing {
    /// Pay-per-token (API key / usage credits): tokens cost money.
    Usage,
    /// Flat-rate subscription (e.g. Claude plan OAuth): tokens are tracked
    /// but their marginal cost is zero.
    Subscription,
}

/// Token counts normalized across providers: `input`, `cache_read`, and
/// `cache_write` are disjoint (OpenAI reports cached tokens as a subset of
/// prompt tokens; the parser subtracts them out so one cost formula works).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
}

impl TokenUsage {
    pub fn cost_usd(&self, rate: &ModelRate) -> f64 {
        (self.input as f64 * rate.input
            + self.output as f64 * rate.output
            + self.cache_read as f64 * rate.cache_read
            + self.cache_write as f64 * rate.cache_write)
            / 1_000_000.0
    }
}

/// On-disk override file (`pricing.json`), all sections optional:
/// `{"hosts": {"llm.internal": "openai"},
///   "billing": {"api.anthropic.com": "subscription"},
///   "models": {"claude-sonnet-5": {"input": 3.0, "output": 15.0}}}`
#[derive(Debug, Default, Deserialize)]
struct PricingFile {
    #[serde(default)]
    hosts: BTreeMap<String, String>,
    #[serde(default)]
    billing: BTreeMap<String, String>,
    #[serde(default)]
    models: BTreeMap<String, ModelRate>,
}

#[derive(Debug, Clone)]
pub struct Pricing {
    hosts: BTreeMap<String, Provider>,
    billing_overrides: BTreeMap<String, Billing>,
    /// Keyed by model-name prefix; the longest matching prefix wins, so
    /// dated releases ("claude-sonnet-5-20250929") match their family entry.
    models: BTreeMap<String, ModelRate>,
}

/// Built-in $/mtok snapshot (July 2026). Override via `pricing.json` when a
/// price changes or a model is missing; the provider default covers the rest.
fn builtin_models() -> BTreeMap<String, ModelRate> {
    let mut m = BTreeMap::new();
    let mut add = |name: &str, input: f64, output: f64, cache_read: f64, cache_write: f64| {
        m.insert(
            name.to_string(),
            ModelRate {
                input,
                output,
                cache_read,
                cache_write,
            },
        );
    };
    // Anthropic (cache_write is the 5-minute rate: 1.25x input).
    add("claude-opus-4", 15.0, 75.0, 1.5, 18.75);
    add("claude-sonnet-4", 3.0, 15.0, 0.3, 3.75);
    add("claude-sonnet-5", 3.0, 15.0, 0.3, 3.75);
    add("claude-3-7-sonnet", 3.0, 15.0, 0.3, 3.75);
    add("claude-haiku-4-5", 1.0, 5.0, 0.1, 1.25);
    add("claude-3-5-haiku", 0.8, 4.0, 0.08, 1.0);
    // OpenAI (no cache-write charge).
    add("gpt-5-nano", 0.05, 0.4, 0.005, 0.0);
    add("gpt-5-mini", 0.25, 2.0, 0.025, 0.0);
    add("gpt-5", 1.25, 10.0, 0.125, 0.0);
    add("gpt-4o-mini", 0.15, 0.6, 0.075, 0.0);
    add("gpt-4o", 2.5, 10.0, 1.25, 0.0);
    add("gpt-4.1-mini", 0.4, 1.6, 0.1, 0.0);
    add("gpt-4.1", 2.0, 8.0, 0.5, 0.0);
    add("o3", 2.0, 8.0, 0.5, 0.0);
    add("o4-mini", 1.1, 4.4, 0.275, 0.0);
    m
}

impl Default for Pricing {
    fn default() -> Self {
        let mut hosts = BTreeMap::new();
        hosts.insert("api.anthropic.com".to_string(), Provider::Anthropic);
        hosts.insert("api.openai.com".to_string(), Provider::OpenAi);
        Pricing {
            hosts,
            billing_overrides: BTreeMap::new(),
            models: builtin_models(),
        }
    }
}

impl Pricing {
    /// Built-ins overlaid with `pricing.json` if present. A malformed file is
    /// reported by the caller (engine reload) and the previous table stays.
    pub fn load() -> anyhow::Result<Self> {
        let mut p = Pricing::default();
        let path = config::pricing_path()?;
        if !path.exists() {
            return Ok(p);
        }
        let text = std::fs::read_to_string(&path)?;
        let file: PricingFile = serde_json::from_str(&text)?;
        for (host, name) in &file.hosts {
            if let Some(provider) = Provider::from_name(name) {
                p.hosts.insert(host.to_ascii_lowercase(), provider);
            }
        }
        for (host, mode) in &file.billing {
            let billing = match mode.to_ascii_lowercase().as_str() {
                "subscription" => Billing::Subscription,
                _ => Billing::Usage,
            };
            p.billing_overrides
                .insert(host.to_ascii_lowercase(), billing);
        }
        p.models.extend(file.models.clone());
        Ok(p)
    }

    pub fn provider_for_host(&self, host: &str) -> Option<Provider> {
        self.hosts.get(host).copied()
    }

    /// Longest model-name prefix in the table, else the provider default.
    pub fn rate_for(&self, provider: Provider, model: Option<&str>) -> ModelRate {
        let Some(model) = model else {
            return provider.default_rate();
        };
        self.models
            .iter()
            .filter(|(prefix, _)| model.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|(_, rate)| *rate)
            .unwrap_or_else(|| provider.default_rate())
    }

    /// Is `model` covered by the pricing table (any prefix entry matches)?
    /// The soft-landing downgrade (plan 003) uses this to flag a map naming
    /// a model nothing prices — likely a typo the provider will reject. The
    /// request forwards as configured either way; this only shapes the log.
    pub fn knows_model(&self, model: &str) -> bool {
        self.models
            .keys()
            .any(|prefix| model.starts_with(prefix.as_str()))
    }

    /// How this request is billed. An explicit `pricing.json` override wins;
    /// otherwise Anthropic requests authenticated with OAuth (`Authorization:
    /// Bearer`, no `x-api-key`) are Claude-plan subscription traffic, and
    /// everything else is pay-per-token.
    pub fn billing_for(
        &self,
        provider: Provider,
        host: &str,
        headers: &[(String, String)],
    ) -> Billing {
        if let Some(b) = self.billing_overrides.get(host) {
            return *b;
        }
        if provider == Provider::Anthropic {
            let has_api_key = headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("x-api-key"));
            let has_bearer = headers.iter().any(|(n, v)| {
                n.eq_ignore_ascii_case("authorization")
                    && v.len() >= 7
                    && v[..7].eq_ignore_ascii_case("bearer ")
            });
            if !has_api_key && has_bearer {
                return Billing::Subscription;
            }
        }
        Billing::Usage
    }
}

/// Split one request's token cost into (billable, reference) dollars.
/// Usage-billed tokens cost real money and have no reference figure;
/// subscription tokens cost nothing but carry what the same tokens would
/// have billed at API rates (plan 019). Exactly one side is ever nonzero,
/// so no total can sum the two by accident.
pub fn split_cost(billing: Billing, usage: &TokenUsage, rate: &ModelRate) -> (f64, f64) {
    let api = usage.cost_usd(rate);
    match billing {
        Billing::Usage => (api, 0.0),
        Billing::Subscription => (0.0, api),
    }
}

/// The key a request's tokens accrue under in the meter: the model name,
/// tagged when the traffic is plan-covered so the two billing modes never
/// blend in one row.
pub fn model_key(model: Option<&str>, billing: Billing) -> String {
    let model = model.unwrap_or("(unknown model)");
    match billing {
        Billing::Usage => model.to_string(),
        Billing::Subscription => format!("{model} [subscription]"),
    }
}

/// The `"model"` field of an LLM request body, if the body is JSON.
pub fn parse_model(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(v.get("model")?.as_str()?.to_string())
}

fn get_u64(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(|n| n.as_u64()).unwrap_or(0)
}

/// Normalize a provider `usage` object. Returns None when the object carries
/// no token counts (e.g. OpenAI stream chunks with `"usage": null`).
fn usage_from_value(provider: Provider, usage: &serde_json::Value) -> Option<TokenUsage> {
    if !usage.is_object() {
        return None;
    }
    let parsed = match provider {
        Provider::Anthropic => TokenUsage {
            input: get_u64(usage, "input_tokens"),
            output: get_u64(usage, "output_tokens"),
            cache_read: get_u64(usage, "cache_read_input_tokens"),
            cache_write: get_u64(usage, "cache_creation_input_tokens"),
        },
        Provider::OpenAi => {
            // Chat Completions says prompt/completion, Responses says
            // input/output; cached tokens are reported inside the prompt
            // count and billed at the cache-read rate, so split them out.
            let prompt = get_u64(usage, "prompt_tokens").max(get_u64(usage, "input_tokens"));
            let output = get_u64(usage, "completion_tokens").max(get_u64(usage, "output_tokens"));
            let cached = usage
                .get("prompt_tokens_details")
                .or_else(|| usage.get("input_tokens_details"))
                .map(|d| get_u64(d, "cached_tokens"))
                .unwrap_or(0);
            TokenUsage {
                input: prompt.saturating_sub(cached),
                output,
                cache_read: cached,
                cache_write: 0,
            }
        }
    };
    if parsed == TokenUsage::default() {
        None
    } else {
        Some(parsed)
    }
}

/// Find the `usage` object in a response value: top-level (Anthropic
/// Messages, OpenAI Chat/Responses), under `message` (Anthropic
/// `message_start` stream events), or under `response` (OpenAI Responses
/// stream `response.completed`).
fn find_usage(v: &serde_json::Value) -> Option<&serde_json::Value> {
    v.get("usage")
        .or_else(|| v.get("message")?.get("usage"))
        .or_else(|| v.get("response")?.get("usage"))
}

/// Token usage from a fully buffered JSON response body.
pub fn parse_usage_json(provider: Provider, body: &[u8]) -> Option<TokenUsage> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    usage_from_value(provider, find_usage(&v)?)
}

/// Token usage from a fully buffered body that is really an SSE stream — a
/// concatenation of `data:` events rather than one JSON object. Some provider
/// backends stream SSE without labeling the response `text/event-stream` (e.g.
/// ChatGPT's Codex endpoint, `chatgpt.com/backend-api/codex/responses`), so a
/// whole-body JSON parse fails and the counts would otherwise be lost. Returns
/// `None` for a plain JSON body (it carries no `data:` lines), so callers can
/// use it purely as a fallback after `parse_usage_json`.
pub fn scan_usage_sse(provider: Provider, body: &[u8]) -> Option<TokenUsage> {
    let mut scanner = SseUsageScanner::new(provider);
    scanner.feed(body);
    scanner.finish()
}

/// A single SSE `data:` line longer than this disables scanning for the
/// stream; the meter falls back to the byte estimate rather than holding an
/// unbounded line buffer.
const MAX_SSE_LINE: usize = 1 << 20; // 1 MiB

/// Incremental `usage` extraction from an SSE stream, fed chunk by chunk as
/// bytes are relayed to the client. Never buffers more than one line, so the
/// zero-copy passthrough guarantee holds. Counters merge by `max`, which
/// handles both Anthropic's split reporting (`message_start` carries input,
/// `message_delta` carries the final cumulative output) and OpenAI's single
/// final-chunk usage.
pub struct SseUsageScanner {
    provider: Provider,
    line: Vec<u8>,
    best: TokenUsage,
    found: bool,
    dead: bool,
}

impl SseUsageScanner {
    pub fn new(provider: Provider) -> Self {
        SseUsageScanner {
            provider,
            line: Vec::new(),
            best: TokenUsage::default(),
            found: false,
            dead: false,
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        if self.dead {
            return;
        }
        for &b in chunk {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.scan_line(&line);
            } else {
                self.line.push(b);
                if self.line.len() > MAX_SSE_LINE {
                    self.dead = true;
                    self.line = Vec::new();
                    return;
                }
            }
        }
    }

    fn scan_line(&mut self, line: &[u8]) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(payload) = line.strip_prefix(b"data:") else {
            return;
        };
        let payload = payload.strip_prefix(b" ").unwrap_or(payload);
        // Cheap pre-filter: most stream events are content deltas with no
        // usage object; skip the JSON parse for those.
        if !payload.starts_with(b"{") || !contains(payload, b"\"usage\"") {
            return;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(payload) else {
            return;
        };
        let Some(usage) = find_usage(&v).and_then(|u| usage_from_value(self.provider, u)) else {
            return;
        };
        self.best.input = self.best.input.max(usage.input);
        self.best.output = self.best.output.max(usage.output);
        self.best.cache_read = self.best.cache_read.max(usage.cache_read);
        self.best.cache_write = self.best.cache_write.max(usage.cache_write);
        self.found = true;
    }

    /// The merged usage, if the stream reported any and scanning stayed
    /// within bounds. Flushes a final unterminated line first (a stream can
    /// end without a trailing newline).
    pub fn finish(mut self) -> Option<TokenUsage> {
        if !self.dead && !self.line.is_empty() {
            let line = std::mem::take(&mut self.line);
            self.scan_line(&line);
        }
        if self.found && !self.dead {
            Some(self.best)
        } else {
            None
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn knows_model_matches_prefixes_only() {
        let p = Pricing::default();
        assert!(p.knows_model("claude-sonnet-5"));
        assert!(p.knows_model("claude-sonnet-5-20250929"), "dated release");
        assert!(!p.knows_model("totally-unknown-model"));
        assert!(!p.knows_model(""));
    }

    #[test]
    fn longest_prefix_wins() {
        let p = Pricing::default();
        let mini = p.rate_for(Provider::OpenAi, Some("gpt-5-mini-2025-08-07"));
        let full = p.rate_for(Provider::OpenAi, Some("gpt-5-2025-08-07"));
        assert_eq!(mini.input, 0.25);
        assert_eq!(full.input, 1.25);
        // Unknown model falls back to the provider default, never $0.
        let unknown = p.rate_for(Provider::Anthropic, Some("claude-fable-5"));
        assert_eq!(unknown, Provider::Anthropic.default_rate());
    }

    #[test]
    fn anthropic_usage_parses_with_cache_fields() {
        let body = br#"{"id":"msg_1","model":"claude-sonnet-5","usage":
            {"input_tokens":100,"output_tokens":50,
             "cache_read_input_tokens":900,"cache_creation_input_tokens":30}}"#;
        let u = parse_usage_json(Provider::Anthropic, body).unwrap();
        assert_eq!(
            u,
            TokenUsage {
                input: 100,
                output: 50,
                cache_read: 900,
                cache_write: 30
            }
        );
        let rate = Pricing::default().rate_for(Provider::Anthropic, Some("claude-sonnet-5"));
        let cost = u.cost_usd(&rate);
        // 100*3 + 50*15 + 900*0.3 + 30*3.75 per mtok
        assert!((cost - 0.0014325).abs() < 1e-9, "cost was {cost}");
    }

    #[test]
    fn openai_cached_tokens_are_split_out_of_prompt() {
        let body = br#"{"usage":{"prompt_tokens":1000,"completion_tokens":20,
            "prompt_tokens_details":{"cached_tokens":600}}}"#;
        let u = parse_usage_json(Provider::OpenAi, body).unwrap();
        assert_eq!(u.input, 400);
        assert_eq!(u.cache_read, 600);
        assert_eq!(u.output, 20);
    }

    #[test]
    fn openai_responses_api_field_names() {
        let body = br#"{"usage":{"input_tokens":36,"output_tokens":87,
            "input_tokens_details":{"cached_tokens":12}}}"#;
        let u = parse_usage_json(Provider::OpenAi, body).unwrap();
        assert_eq!(u.input, 24);
        assert_eq!(u.cache_read, 12);
        assert_eq!(u.output, 87);
    }

    #[test]
    fn no_usage_means_none() {
        assert!(parse_usage_json(Provider::OpenAi, br#"{"usage":null}"#).is_none());
        assert!(parse_usage_json(Provider::Anthropic, b"not json").is_none());
        assert!(parse_usage_json(Provider::Anthropic, br#"{"usage":{}}"#).is_none());
    }

    #[test]
    fn sse_scanner_merges_anthropic_start_and_delta() {
        let mut s = SseUsageScanner::new(Provider::Anthropic);
        // Split feeds mid-line to exercise the incremental buffer.
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5\",",
            "\"usage\":{\"input_tokens\":200,\"output_tokens\":1,\"cache_read_input_tokens\":50}}}\n",
            "\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"usage of the word usage\"}}\n",
            "\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":75}}\n",
        );
        let bytes = stream.as_bytes();
        s.feed(&bytes[..40]);
        s.feed(&bytes[40..]);
        let u = s.finish().unwrap();
        assert_eq!(
            u,
            TokenUsage {
                input: 200,
                output: 75,
                cache_read: 50,
                cache_write: 0
            }
        );
    }

    #[test]
    fn sse_scanner_openai_final_chunk() {
        let mut s = SseUsageScanner::new(Provider::OpenAi);
        s.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n");
        s.feed(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n",
        );
        s.feed(b"data: [DONE]\n");
        let u = s.finish().unwrap();
        assert_eq!(u.input, 10);
        assert_eq!(u.output, 5);
    }

    #[test]
    fn sse_scanner_gives_up_on_oversized_lines() {
        let mut s = SseUsageScanner::new(Provider::Anthropic);
        s.feed(b"data: {\"message\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}}\n");
        s.feed(&vec![b'x'; MAX_SSE_LINE + 2]);
        assert!(s.finish().is_none(), "oversized line must fall back");
    }

    #[test]
    fn scan_usage_sse_reads_a_mislabeled_buffered_stream() {
        // OpenAI Responses-style SSE delivered as a buffered body (no
        // text/event-stream label, as ChatGPT's Codex backend does): the final
        // `response.completed` carries `response.usage`.
        let body = concat!(
            "event: response.output_text.delta\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n",
            "\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":300,\"output_tokens\":40,\"input_tokens_details\":{\"cached_tokens\":250}}}}\n",
        );
        let u = scan_usage_sse(Provider::OpenAi, body.as_bytes()).unwrap();
        assert_eq!(u.input, 50); // 300 prompt - 250 cached
        assert_eq!(u.cache_read, 250);
        assert_eq!(u.output, 40);
        // A plain JSON body carries no `data:` lines, so the fallback is quiet
        // (callers use it only after parse_usage_json returns None).
        assert!(scan_usage_sse(Provider::OpenAi, br#"{"usage":{"input_tokens":5}}"#).is_none());
    }

    #[test]
    fn anthropic_oauth_is_subscription_api_key_is_usage() {
        let p = Pricing::default();
        let sub = p.billing_for(
            Provider::Anthropic,
            "api.anthropic.com",
            &hdrs(&[("Authorization", "Bearer sk-ant-oat01-abc")]),
        );
        assert_eq!(sub, Billing::Subscription);
        let usage = p.billing_for(
            Provider::Anthropic,
            "api.anthropic.com",
            &hdrs(&[
                ("x-api-key", "sk-ant-api03-abc"),
                ("Authorization", "Bearer something"),
            ]),
        );
        assert_eq!(usage, Billing::Usage);
        // OpenAI bearer is just an API key.
        let openai = p.billing_for(
            Provider::OpenAi,
            "api.openai.com",
            &hdrs(&[("Authorization", "Bearer sk-proj-abc")]),
        );
        assert_eq!(openai, Billing::Usage);
    }

    #[test]
    fn pricing_file_overlays_builtins() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        std::fs::write(
            dir.path().join("pricing.json"),
            r#"{"hosts": {"llm.corp.internal": "openai"},
                "billing": {"api.anthropic.com": "subscription"},
                "models": {"claude-sonnet-5": {"input": 9.9, "output": 99.0}}}"#,
        )
        .unwrap();
        let p = Pricing::load().unwrap();
        assert_eq!(
            p.provider_for_host("llm.corp.internal"),
            Some(Provider::OpenAi)
        );
        assert_eq!(
            p.billing_for(Provider::Anthropic, "api.anthropic.com", &[]),
            Billing::Subscription
        );
        assert_eq!(
            p.rate_for(Provider::Anthropic, Some("claude-sonnet-5"))
                .input,
            9.9
        );
        // Untouched builtins survive the overlay.
        assert_eq!(
            p.provider_for_host("api.openai.com"),
            Some(Provider::OpenAi)
        );
    }

    #[test]
    fn split_cost_never_mixes_billable_and_reference() {
        let rate = Pricing::default().rate_for(Provider::Anthropic, Some("claude-sonnet-5"));
        let u = TokenUsage {
            input: 1000,
            output: 200,
            cache_read: 5000,
            cache_write: 100,
        };
        let api = u.cost_usd(&rate);
        assert!(api > 0.0);
        // Usage-billed: real cost, no reference figure.
        assert_eq!(split_cost(Billing::Usage, &u, &rate), (api, 0.0));
        // Subscription: zero marginal cost, full API-equivalent reference —
        // cache reads and writes priced at their own multipliers.
        assert_eq!(split_cost(Billing::Subscription, &u, &rate), (0.0, api));
    }

    #[test]
    fn model_key_tags_subscription() {
        assert_eq!(
            model_key(Some("claude-sonnet-5"), Billing::Subscription),
            "claude-sonnet-5 [subscription]"
        );
        assert_eq!(model_key(None, Billing::Usage), "(unknown model)");
    }
}
