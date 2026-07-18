//! Budget soft-landing (plan 003): the band between "fine" and "dead".
//!
//! Past a configurable share of the monthly budget, requests naming a model
//! on the left of the policy's downgrade map are rewritten to the cheaper
//! model on the right, so the agent keeps working instead of hitting the
//! kill switch at speed. This module owns the rewrite itself; the band check,
//! Pro gate, audit event, and response marker live in the proxy pipeline.
//!
//! The rewrite is byte-surgical on the client's original bytes, like the
//! prompt-cache repair splice: serde_json would reorder object keys on a
//! round-trip, churning everything the provider caches. Only the model
//! value's bytes change. Anything that can't be rewritten with certainty — no
//! JSON object, no string `model` member, no map entry, an edit that would
//! not re-parse — passes through untouched: never guess, never break traffic
//! over a cost feature.

use std::collections::BTreeMap;

/// A completed model rewrite: the new body plus the mapping applied, for the
/// audit note and the response marker.
#[derive(Debug)]
pub struct Rewrite {
    pub body: Vec<u8>,
    pub from: String,
    pub to: String,
}

/// Rewrite the top-level `"model"` member (the field both the Anthropic and
/// OpenAI JSON body shapes use) per the downgrade map. `None` means no
/// rewrite applies and the body must forward unchanged: the body isn't a
/// JSON object carrying a string model, the map has no entry for it, the
/// mapping is the identity, or the edit failed its own re-parse check.
pub fn rewrite_model(body: &[u8], map: &BTreeMap<String, String>) -> Option<Rewrite> {
    // The authoritative parse: same reader the accounting uses.
    let from = crate::pricing::parse_model(body)?;
    let to = map.get(&from)?;
    if *to == from {
        return None;
    }
    let (vstart, vend) = model_span(body)?;
    // Encode the replacement as a JSON string so a map value that needs
    // escaping can't produce malformed output.
    let encoded = serde_json::to_string(to).ok()?;
    let mut out = Vec::with_capacity(body.len() - (vend - vstart) + encoded.len());
    out.extend_from_slice(&body[..vstart]);
    out.extend_from_slice(encoded.as_bytes());
    out.extend_from_slice(&body[vend..]);
    // Sanity: the edit must re-parse and actually carry the new model (a
    // duplicate-key body, say, would still read as the old one). Anything
    // else forwards the original untouched.
    if crate::pricing::parse_model(&out).as_deref() != Some(to.as_str()) {
        return None;
    }
    Some(Rewrite {
        body: out,
        from,
        to: to.clone(),
    })
}

/// Byte span (start..end, quotes included) of the top-level `"model"` string
/// value. `None` when the body isn't an object or the member isn't a string.
fn model_span(body: &[u8]) -> Option<(usize, usize)> {
    let root_open = crate::cache::skip_ws(body, 0);
    if body.get(root_open) != Some(&b'{') {
        return None;
    }
    let (vstart, vend) = crate::cache::object_member_value(body, root_open, "model")?;
    if body.get(vstart) != Some(&b'"') {
        return None;
    }
    Some((vstart, vend))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(f, t)| (f.to_string(), t.to_string()))
            .collect()
    }

    #[test]
    fn rewrites_anthropic_shape_surgically() {
        let body = br#"{"model": "claude-opus-4", "max_tokens": 64,
            "system":[{"type":"text","text":"be brief"}],
            "messages":[{"role":"user","content":"hi"}]}"#;
        let rw = rewrite_model(body, &map(&[("claude-opus-4", "claude-sonnet-5")]))
            .expect("mapped model must rewrite");
        assert_eq!(rw.from, "claude-opus-4");
        assert_eq!(rw.to, "claude-sonnet-5");
        let expected = String::from_utf8_lossy(body).replace("claude-opus-4", "claude-sonnet-5");
        // Byte-surgical: only the model value changed, nothing reordered.
        assert_eq!(String::from_utf8(rw.body).unwrap(), expected);
    }

    #[test]
    fn rewrites_openai_shape() {
        let body =
            br#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-5","stream":true}"#;
        let rw = rewrite_model(body, &map(&[("gpt-5", "gpt-5-mini")])).expect("rewrite");
        assert_eq!(
            String::from_utf8(rw.body).unwrap(),
            r#"{"messages":[{"role":"user","content":"hi"}],"model":"gpt-5-mini","stream":true}"#
        );
    }

    #[test]
    fn unmapped_absent_or_malformed_model_passes_through() {
        let m = map(&[("claude-opus-4", "claude-sonnet-5")]);
        // Model present but not in the map.
        assert!(rewrite_model(br#"{"model":"claude-haiku-4-5"}"#, &m).is_none());
        // No model member at all.
        assert!(rewrite_model(br#"{"messages":[]}"#, &m).is_none());
        // Model is not a string.
        assert!(rewrite_model(br#"{"model":42}"#, &m).is_none());
        // Not JSON / not an object.
        assert!(rewrite_model(b"not json at all", &m).is_none());
        assert!(rewrite_model(br#"["model","claude-opus-4"]"#, &m).is_none());
        assert!(rewrite_model(b"", &m).is_none());
        // Empty map: nothing ever rewrites.
        assert!(rewrite_model(br#"{"model":"claude-opus-4"}"#, &BTreeMap::new()).is_none());
    }

    #[test]
    fn model_span_guards_hold_on_their_own() {
        // rewrite_model reaches model_span only after parse_model found a
        // string model, so these defensive arms are pinned directly: a
        // non-object root and a first-duplicate non-string value must both
        // refuse a span rather than guess.
        assert!(model_span(br#"["model","gpt-5"]"#).is_none());
        assert!(model_span(br#"{"model":42}"#).is_none());
    }

    #[test]
    fn identity_mapping_is_a_no_op() {
        let m = map(&[("gpt-5", "gpt-5")]);
        assert!(rewrite_model(br#"{"model":"gpt-5"}"#, &m).is_none());
    }

    #[test]
    fn model_named_in_message_content_is_untouched() {
        // Only the top-level member rewrites; the same string inside content
        // stays exactly as the client wrote it.
        let body = br#"{"model":"gpt-5","messages":[{"role":"user","content":"use gpt-5 please, \"model\":\"gpt-5\""}]}"#;
        let rw = rewrite_model(body, &map(&[("gpt-5", "gpt-5-mini")])).expect("rewrite");
        let text = String::from_utf8(rw.body).unwrap();
        assert!(text.starts_with(r#"{"model":"gpt-5-mini","#));
        assert!(text.contains(r#"use gpt-5 please, \"model\":\"gpt-5\""#));
    }

    #[test]
    fn duplicate_model_keys_pass_through_rather_than_guess() {
        // serde_json reads the last duplicate; the span scanner finds the
        // first. The re-parse check catches the disagreement and the body
        // forwards untouched instead of half-rewritten.
        let body = br#"{"model":"gpt-5","model":"gpt-4o"}"#;
        assert!(rewrite_model(body, &map(&[("gpt-4o", "gpt-4o-mini")])).is_none());
    }

    #[test]
    fn target_needing_escapes_stays_valid_json() {
        let m = map(&[("gpt-5", "weird\"name")]);
        let rw = rewrite_model(br#"{"model":"gpt-5","messages":[]}"#, &m).expect("rewrite");
        let v: serde_json::Value = serde_json::from_slice(&rw.body).unwrap();
        assert_eq!(v["model"], "weird\"name");
    }

    #[test]
    fn whitespace_and_unicode_bodies_survive() {
        let body = "{\n  \"model\" : \"gpt-5\" ,\n  \"messages\": [{\"content\":\"héllo ☃\"}]\n}";
        let rw = rewrite_model(body.as_bytes(), &map(&[("gpt-5", "gpt-5-nano")])).expect("rw");
        let text = String::from_utf8(rw.body).unwrap();
        assert!(text.contains("\"model\" : \"gpt-5-nano\" ,"));
        assert!(text.contains("héllo ☃"));
    }
}
