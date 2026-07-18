//! Structured, comment-preserving edits to `policy.toml` for the
//! `decoyrail policy` subcommands (list, add, set, rm, mv, default, flush,
//! reset, edit) — the firewall-style CLI over the egress rules.
//!
//! Every mutation edits the TOML tree in place, so comments and the rules a
//! command doesn't touch survive byte-for-byte. Rules are an array of tables
//! (`[[rule]]`); `toml_edit` renders tables in the order of each table's
//! `position()`, not array order, so any structural change (insert, move,
//! delete) renumbers positions afterwards to keep the rules in list order with
//! `[dlp]` last. Nothing here writes the file — the CLI calls [`write_policy`],
//! the single validated, backed-up, atomic write path, so a running proxy can
//! never read a broken or partial policy.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use toml_edit::{value, Array, ArrayOfTables, DocumentMut, Item, Table};

use crate::config;
use crate::policy::{Action, Policy};

/// The fields of a rule as supplied on the command line. `None` means "leave
/// unchanged" (for `set`) or "omit" (for `add`); it never means "clear".
#[derive(Default)]
pub struct RuleEdit {
    pub name: Option<String>,
    pub hosts: Option<Vec<String>>,
    pub methods: Option<Vec<String>>,
    pub path_prefixes: Option<Vec<String>>,
    pub action: Option<String>,
    pub allow_secrets: Option<Vec<String>>,
}

/// Where a rule goes when added or moved. `iptables -A` is `End`; `-I` is
/// `At`/`Before`/`After`.
pub enum Anchor {
    End,
    /// 1-based target position (clamped to the end).
    At(usize),
    /// Immediately before the named/positioned rule.
    Before(String),
    /// Immediately after the named/positioned rule.
    After(String),
}

/// The policy document as an editable TOML tree.
pub struct PolicyDoc {
    doc: DocumentMut,
}

impl PolicyDoc {
    /// Load the live policy, materializing the shipped default on first run so
    /// every `policy` subcommand has something to operate on (matching
    /// `Policy::load_or_default`).
    pub fn load() -> Result<Self> {
        let _ = Policy::load_or_default()?; // writes the default if absent
        let text = std::fs::read_to_string(config::policy_path()?)?;
        Self::parse(&text)
    }

    /// Parse policy text into an editable tree (no filesystem access).
    pub fn parse(text: &str) -> Result<Self> {
        let doc = text.parse::<DocumentMut>().context("parsing policy.toml")?;
        Ok(Self { doc })
    }

    /// Render back to TOML text.
    pub fn render(&self) -> String {
        self.doc.to_string()
    }

    /// Validate and persist this document (see [`write_policy`]); returns the
    /// backup path. `source` names the CLI surface for the audit event.
    pub fn save(&self, source: &str) -> Result<PathBuf> {
        write_policy(&self.render(), source)
    }

    fn aot(&self) -> Option<&ArrayOfTables> {
        self.doc.get("rule").and_then(Item::as_array_of_tables)
    }

    fn aot_mut(&mut self) -> Option<&mut ArrayOfTables> {
        self.doc
            .get_mut("rule")
            .and_then(Item::as_array_of_tables_mut)
    }

    fn tables(&self) -> Vec<Table> {
        self.aot()
            .map(|a| a.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The rule names in evaluation order (for addressing and messages).
    pub fn names(&self) -> Vec<String> {
        self.tables().iter().map(rule_name).collect()
    }

    pub fn len(&self) -> usize {
        self.aot().map(ArrayOfTables::len).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add a rule built from `edit`, placed per `anchor`.
    pub fn add(&mut self, edit: &RuleEdit, anchor: &Anchor) -> Result<()> {
        let new = build_table(edit)?;
        let name = rule_name(&new);
        let mut tables = self.tables();
        if tables.iter().any(|t| rule_name(t) == name) {
            bail!("a rule named '{name}' already exists; pick another name or `set` it");
        }
        let idx = resolve_anchor(anchor, &tables)?;
        tables.insert(idx, new);
        self.rebuild(tables);
        Ok(())
    }

    /// Update fields of an existing rule (addressed by name or 1-based
    /// position). Returns the rule's name after the edit.
    pub fn set(&mut self, addr: &str, edit: &RuleEdit) -> Result<String> {
        let i = self.resolve(addr)?;
        if let Some(new_name) = &edit.name {
            if new_name != &self.names()[i] && self.names().iter().any(|n| n == new_name) {
                bail!("a rule named '{new_name}' already exists");
            }
        }
        if let Some(a) = &edit.action {
            Action::parse(a)?; // reject bad actions before touching the tree
        }
        let t = self
            .aot_mut()
            .and_then(|a| a.get_mut(i))
            .expect("index resolved");
        if let Some(v) = &edit.name {
            t["name"] = value(v.as_str());
        }
        if let Some(v) = &edit.hosts {
            t["hosts"] = value(str_array(v));
        }
        if let Some(v) = &edit.methods {
            set_list(t, "methods", v);
        }
        if let Some(v) = &edit.path_prefixes {
            set_list(t, "path_prefixes", v);
        }
        if let Some(v) = &edit.action {
            t["action"] = value(v.as_str());
        }
        if let Some(v) = &edit.allow_secrets {
            set_list(t, "allow_secrets", v);
        }
        Ok(rule_name(t))
    }

    /// Delete a rule; returns its name.
    pub fn remove(&mut self, addr: &str) -> Result<String> {
        let i = self.resolve(addr)?;
        let mut tables = self.tables();
        let removed = rule_name(&tables[i]);
        tables.remove(i);
        self.rebuild(tables);
        Ok(removed)
    }

    /// Move a rule to a new spot; returns its name.
    pub fn move_rule(&mut self, addr: &str, anchor: &Anchor) -> Result<String> {
        let i = self.resolve(addr)?;
        let mut tables = self.tables();
        let moved = tables.remove(i);
        let name = rule_name(&moved);
        // Resolve the anchor against the list with the rule already removed, so
        // Before/After a neighbor and a 1-based target both land as expected.
        let idx = resolve_anchor(anchor, &tables)?;
        tables.insert(idx, moved);
        self.rebuild(tables);
        Ok(name)
    }

    /// Remove all rules, keeping the default action.
    pub fn flush(&mut self) {
        if let Some(a) = self.aot_mut() {
            a.clear();
        }
        self.renumber();
    }

    pub fn set_default(&mut self, action: &str) -> Result<()> {
        let a = Action::parse(action)?;
        self.doc["default_action"] = value(a.as_str());
        Ok(())
    }

    pub fn set_escalate_fallback(&mut self, action: &str) -> Result<()> {
        let a = Action::parse(action)?;
        if !matches!(a, Action::Allow | Action::Deny | Action::Warn) {
            bail!("the escalate fallback must be allow, deny, or warn, not escalate");
        }
        self.doc["escalate_fallback"] = value(a.as_str());
        Ok(())
    }

    /// Resolve a rule address (name or 1-based position) to a 0-based index.
    fn resolve(&self, addr: &str) -> Result<usize> {
        index_of(&self.tables(), addr)
    }

    /// Replace the rule array with `tables` and fix up positions so the
    /// renderer keeps list order with `[dlp]` last.
    fn rebuild(&mut self, tables: Vec<Table>) {
        let mut aot = ArrayOfTables::new();
        for t in tables {
            aot.push(t);
        }
        self.doc["rule"] = Item::ArrayOfTables(aot);
        self.renumber();
    }

    /// `toml_edit` stable-sorts tables by `position()` when rendering, and the
    /// parser hands out monotonic positions matching original file order — so
    /// after any reshuffle the positions are stale. Renumber the rules to
    /// 1..=N in array order and push `[dlp]` to N+1; the root keys stay at
    /// position 0 and thus render first.
    fn renumber(&mut self) {
        let n = self.len();
        if let Some(aot) = self.aot_mut() {
            for (i, t) in aot.iter_mut().enumerate() {
                t.set_position(i + 1);
            }
        }
        if let Some(dlp) = self.doc.get_mut("dlp").and_then(Item::as_table_mut) {
            dlp.set_position(n + 1);
        }
    }
}

/// Build a fresh `[[rule]]` table from an edit, in the canonical key order.
fn build_table(edit: &RuleEdit) -> Result<Table> {
    let name = edit
        .name
        .clone()
        .ok_or_else(|| anyhow!("a rule needs a name"))?;
    let hosts = edit.hosts.clone().unwrap_or_default();
    if hosts.is_empty() {
        bail!("rule '{name}' needs at least one --host");
    }
    let action = edit
        .action
        .clone()
        .ok_or_else(|| anyhow!("rule '{name}' needs an --action"))?;
    Action::parse(&action)?;

    let mut t = Table::new();
    t.set_implicit(false);
    t["name"] = value(name.as_str());
    t["hosts"] = value(str_array(&hosts));
    if let Some(m) = &edit.methods {
        if !m.is_empty() {
            t["methods"] = value(str_array(m));
        }
    }
    if let Some(p) = &edit.path_prefixes {
        if !p.is_empty() {
            t["path_prefixes"] = value(str_array(p));
        }
    }
    t["action"] = value(action.to_ascii_lowercase());
    if let Some(s) = &edit.allow_secrets {
        if !s.is_empty() {
            t["allow_secrets"] = value(str_array(s));
        }
    }
    Ok(t)
}

/// Set an optional list key, or remove it when the list is empty.
fn set_list(t: &mut Table, key: &str, items: &[String]) {
    if items.is_empty() {
        t.remove(key);
    } else {
        t[key] = value(str_array(items));
    }
}

fn str_array(items: &[String]) -> Array {
    let mut a = Array::new();
    for s in items {
        a.push(s.as_str());
    }
    a
}

fn rule_name(t: &Table) -> String {
    t.get("name")
        .and_then(Item::as_str)
        .unwrap_or("")
        .to_string()
}

/// Resolve a name-or-position address against a list of rule tables.
fn index_of(tables: &[Table], addr: &str) -> Result<usize> {
    if let Ok(pos) = addr.parse::<usize>() {
        if pos == 0 || pos > tables.len() {
            bail!(
                "no rule at position {pos} ({})",
                match tables.len() {
                    0 => "the policy has no rules".to_string(),
                    n => format!("positions are 1..={n}"),
                }
            );
        }
        return Ok(pos - 1);
    }
    let hits: Vec<usize> = tables
        .iter()
        .enumerate()
        .filter(|(_, t)| rule_name(t) == addr)
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [] => bail!("no rule named '{addr}'"),
        [i] => Ok(*i),
        many => bail!(
            "'{addr}' is ambiguous: rules at positions {} share that name; address by position instead",
            many.iter()
                .map(|i| (i + 1).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Resolve an anchor to a 0-based insert index within `tables`.
fn resolve_anchor(anchor: &Anchor, tables: &[Table]) -> Result<usize> {
    Ok(match anchor {
        Anchor::End => tables.len(),
        Anchor::At(pos) => {
            if *pos == 0 {
                bail!("--at is 1-based; use 1 for the top of the list");
            }
            (*pos - 1).min(tables.len())
        }
        Anchor::Before(a) => index_of(tables, a)?,
        Anchor::After(a) => index_of(tables, a)? + 1,
    })
}

/// The CLI write path for the policy. Rejects any text that doesn't parse as
/// a `Policy` (so the file on disk always loads), then hands off to
/// `integrity::install` for the backed-up, recorded, atomic, audited write.
/// Returns the backup path.
///
/// One gate first: the file being edited must itself be trusted. A CLI
/// mutation rewrites the whole document, so editing on top of a tampered
/// file would launder the tamper into a blessed policy nobody reviewed.
/// `decoyrail policy sign` (review and confirm) and `decoyrail policy reset`
/// (fresh defaults) are the two ways out of that state.
pub fn write_policy(new_text: &str, source: &str) -> Result<PathBuf> {
    toml::from_str::<Policy>(new_text)
        .context("refusing to write: the result is not a valid policy")?;
    let path = config::policy_path()?;
    if path.exists() {
        let current = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let verdict = crate::integrity::verify(&current)?;
        if verdict != crate::integrity::Verdict::Trusted {
            anyhow::bail!(
                "refusing to edit an untrusted policy: {}",
                crate::integrity::untrusted_message(verdict)
            );
        }
    }
    crate::integrity::install(new_text, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DEFAULT_POLICY_TOML;

    fn reparse(doc: &PolicyDoc) -> Policy {
        toml::from_str(&doc.render()).expect("edited policy must reparse")
    }

    fn edit(name: &str, host: &str, action: &str) -> RuleEdit {
        RuleEdit {
            name: Some(name.into()),
            hosts: Some(vec![host.into()]),
            action: Some(action.into()),
            ..Default::default()
        }
    }

    #[test]
    fn add_appends_and_reparses() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        let before = reparse(&doc).rules.len();
        doc.add(&edit("stripe", "api.stripe.com", "allow"), &Anchor::End)
            .unwrap();
        let p = reparse(&doc);
        assert_eq!(p.rules.len(), before + 1);
        assert_eq!(p.rules.last().unwrap().name, "stripe");
        assert_eq!(
            p.evaluate("api.stripe.com", "/v1/charges", "POST").action,
            Action::Allow
        );
    }

    #[test]
    fn insert_at_front_wins_first_match() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        // A deny for a github sub-path, inserted at the very top, must win over
        // the broad github allow that sits below it.
        let e = RuleEdit {
            name: Some("block-github-settings".into()),
            hosts: Some(vec!["github.com".into()]),
            path_prefixes: Some(vec!["/settings".into()]),
            action: Some("deny".into()),
            ..Default::default()
        };
        doc.add(&e, &Anchor::At(1)).unwrap();
        let p = reparse(&doc);
        assert_eq!(p.rules[0].name, "block-github-settings");
        assert_eq!(
            p.evaluate("github.com", "/settings/keys", "GET").action,
            Action::Deny
        );
        // Ordinary github traffic still allowed.
        assert_eq!(
            p.evaluate("github.com", "/acme/app", "GET").action,
            Action::Allow
        );
    }

    #[test]
    fn insert_before_and_after_neighbor() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.add(
            &edit("a", "a.example.com", "allow"),
            &Anchor::Before("openai".into()),
        )
        .unwrap();
        doc.add(
            &edit("b", "b.example.com", "allow"),
            &Anchor::After("openai".into()),
        )
        .unwrap();
        let names = doc.names();
        let ai = names.iter().position(|n| n == "a").unwrap();
        let oi = names.iter().position(|n| n == "openai").unwrap();
        let bi = names.iter().position(|n| n == "b").unwrap();
        assert!(ai + 1 == oi && oi + 1 == bi, "{names:?}");
    }

    #[test]
    fn set_changes_only_that_rule_and_keeps_comments() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.set(
            "openai",
            &RuleEdit {
                action: Some("deny".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let rendered = doc.render();
        // Comments above and below the edited rule survive.
        assert!(rendered.contains("# Decoyrail default policy"));
        assert!(rendered.contains("Claude Code's telemetry"));
        assert!(rendered.contains("one-POST exfiltration channel"));
        let p = reparse(&doc);
        assert_eq!(
            p.rules.iter().find(|r| r.name == "openai").unwrap().action,
            Action::Deny
        );
        // A neighbor is untouched.
        assert_eq!(
            p.rules
                .iter()
                .find(|r| r.name == "anthropic")
                .unwrap()
                .action,
            Action::Allow
        );
    }

    #[test]
    fn rename_via_set() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.set(
            "openai",
            &RuleEdit {
                name: Some("openai-api".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(doc.names().iter().any(|n| n == "openai-api"));
        assert!(!doc.names().iter().any(|n| n == "openai"));
    }

    #[test]
    fn remove_deletes_and_reparses() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        let name = doc.remove("openai").unwrap();
        assert_eq!(name, "openai");
        assert!(!reparse(&doc).rules.iter().any(|r| r.name == "openai"));
    }

    #[test]
    fn move_reorders() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.move_rule("openai", &Anchor::At(1)).unwrap();
        assert_eq!(doc.names()[0], "openai");
        // The [dlp] table is still last and still parses to its defaults.
        let p = reparse(&doc);
        assert_eq!(p.dlp.pan, crate::policy::DlpMode::Warn);
        assert!(
            doc.render()
                .trim_end()
                .ends_with("commit-author emails constantly")
                || doc.render().contains("[dlp]")
        );
    }

    #[test]
    fn flush_clears_rules_keeps_default() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.flush();
        let p = reparse(&doc);
        assert!(p.rules.is_empty());
        assert_eq!(p.default_action, Action::Deny);
        // [dlp] survived the flush.
        assert_eq!(p.dlp.pan, crate::policy::DlpMode::Warn);
    }

    #[test]
    fn set_default_and_fallback() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.set_default("allow").unwrap();
        assert_eq!(reparse(&doc).default_action, Action::Allow);
        assert!(doc.set_escalate_fallback("escalate").is_err());
        doc.set_escalate_fallback("allow").unwrap();
        assert_eq!(reparse(&doc).escalate_fallback, Action::Allow);
        // Warn round-trips through both knobs (plan 017: persisting the watch
        // posture needs no new surface).
        doc.set_default("warn").unwrap();
        assert_eq!(reparse(&doc).default_action, Action::Warn);
        doc.set_escalate_fallback("warn").unwrap();
        assert_eq!(reparse(&doc).escalate_fallback, Action::Warn);
    }

    #[test]
    fn add_rule_with_warn_action() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.add(&edit("watched", "api.example.com", "warn"), &Anchor::End)
            .unwrap();
        let p = reparse(&doc);
        assert_eq!(
            p.evaluate("api.example.com", "/", "POST").action,
            Action::Warn
        );
    }

    #[test]
    fn add_and_set_accept_the_route_action() {
        // `decoyrail policy add --action route` must not be rejected (plan
        // 006); the map itself stays a file-edit workflow, so the added rule
        // has an empty map until the user writes one.
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        doc.add(
            &edit("cheap-tier", "api.example.com", "route"),
            &Anchor::End,
        )
        .unwrap();
        let p = reparse(&doc);
        let r = p.rules.iter().find(|r| r.name == "cheap-tier").unwrap();
        assert_eq!(r.action, Action::Route);
        assert!(r.route.is_empty());
        // `set --action route` on an existing rule works the same way, and a
        // hand-written map survives unrelated structured edits byte-for-byte.
        let text = r#"
default_action = "deny"
[[rule]]
name = "r"
hosts = ["a.example.com"]
action = "allow"
route = { "claude-opus-4" = "claude-sonnet-5" }
"#;
        let mut doc = PolicyDoc::parse(text).unwrap();
        doc.set(
            "r",
            &RuleEdit {
                action: Some("route".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let p = reparse(&doc);
        assert_eq!(p.rules[0].action, Action::Route);
        assert_eq!(p.rules[0].route["claude-opus-4"], "claude-sonnet-5");
    }

    #[test]
    fn addressing_by_position_and_duplicate_names() {
        let text = r#"
default_action = "deny"
[[rule]]
name = "dup"
hosts = ["a.example.com"]
action = "allow"
[[rule]]
name = "dup"
hosts = ["b.example.com"]
action = "deny"
"#;
        let doc = PolicyDoc::parse(text).unwrap();
        // Name is ambiguous → error that names positions.
        let err = doc.resolve("dup").unwrap_err().to_string();
        assert!(err.contains("1, 2"), "{err}");
        // Position still resolves.
        assert_eq!(doc.resolve("2").unwrap(), 1);
        assert!(doc.resolve("0").is_err());
        assert!(doc.resolve("3").is_err());
        assert!(doc.resolve("nope").is_err());
    }

    #[test]
    fn add_rejects_duplicate_name_and_bad_action() {
        let mut doc = PolicyDoc::parse(DEFAULT_POLICY_TOML).unwrap();
        assert!(doc
            .add(&edit("openai", "x.example.com", "allow"), &Anchor::End)
            .is_err());
        assert!(doc
            .add(&edit("new", "x.example.com", "nonsense"), &Anchor::End)
            .is_err());
    }

    #[test]
    fn write_policy_rejects_invalid() {
        // Not a valid policy (bad action value) → refused, error, no panic.
        // Validation runs before any filesystem access, so this needs no home.
        assert!(write_policy("default_action = \"sideways\"", "test").is_err());
    }

    #[test]
    fn write_policy_records_and_refuses_untrusted_current() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // A CLI write leaves a file the proxy will trust, with no extra step.
        write_policy(DEFAULT_POLICY_TOML, "test").unwrap();
        assert!(Policy::load_trusted().is_ok());

        // A structured edit through PolicyDoc round-trips the same way.
        let mut doc = PolicyDoc::load().unwrap();
        doc.set_default("deny").unwrap();
        doc.save("test").unwrap();
        assert!(Policy::load_trusted().is_ok());

        // Hand-tamper the file: the next CLI edit refuses rather than
        // laundering the tamper into a blessed policy, and points at sign.
        let path = config::policy_path().unwrap();
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push('#');
        std::fs::write(&path, &text).unwrap();
        let err = write_policy(DEFAULT_POLICY_TOML, "test")
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy sign"), "{err}");
    }
}
