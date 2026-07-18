//! Decoyrail — endpoint firewall for AI agents.
//!
//! Single self-contained binary. Explicit-proxy MVP: no macOS entitlements
//! required. `decoyrail run <cmd>` launches an agent with decoy credentials, its
//! traffic tunneled through an embedded proxy that swaps real secrets in only
//! for approved destinations and blocks/alerts on everything else.

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::Read;

use decoyrail::stats::{fmt_bytes, fmt_tokens};
use decoyrail::{
    audit, ca, cache, config, engine, guard, meter, policy, pricing, proxy, util, vault,
};

use engine::Engine;
use vault::{Location, Vault};

#[derive(Parser)]
#[command(
    name = "decoyrail",
    version = env!("DECOYRAIL_VERSION"),
    about = "Endpoint firewall for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the local TLS-intercepting proxy.
    Proxy(ProxyArgs),
    /// Run a command behind Decoyrail with decoy credentials.
    Run(RunArgs),
    /// Manage the credential vault.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Manage the Decoyrail device CA.
    #[command(subcommand)]
    Ca(CaCmd),
    /// Manage the egress policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Configure filtering for structured sensitive data.
    #[command(subcommand)]
    Dlp(DlpCmd),
    /// Manage vault-key storage.
    #[command(subcommand)]
    Key(KeyCmd),
    /// View the audit log.
    Log(LogArgs),
    /// Analyze spend, tokens, and security events.
    Stats(StatsArgs),
    /// Manage the offline license.
    #[command(subcommand)]
    License(LicenseCmd),
    /// Show spend and budget status.
    Status,
    /// Report prompt-cache hit rate, savings, and invalidations.
    Cache,
    /// Set the monthly spend budget (USD; 0 = unlimited).
    Budget { usd: f64 },
    /// Declare what your subscription plan costs, or show what it absorbed.
    Plan(PlanArgs),
    /// Remove Decoyrail's trusted CA, keychain item, and local state.
    Uninstall(UninstallArgs),
}

#[derive(Args)]
struct PlanArgs {
    /// Monthly plan price in USD, e.g. 200.
    #[arg(long)]
    price: Option<f64>,
    /// Plan name shown in reports, e.g. "Claude Max".
    #[arg(long)]
    label: Option<String>,
    /// Remove the declared plan price.
    #[arg(long, conflicts_with_all = ["price", "label"])]
    clear: bool,
}

#[derive(Args)]
struct UninstallArgs {
    /// Proceed without the confirmation prompt (required when not a TTY).
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct ProxyArgs {
    /// Address the proxy listens on.
    #[arg(long, default_value = config::DEFAULT_PROXY_ADDR)]
    addr: String,
}

#[derive(Args)]
struct RunArgs {
    /// Address for the embedded proxy. Port 0 selects an available port.
    #[arg(long, default_value = "127.0.0.1:0")]
    addr: String,
    /// Pass this env var to the child unchanged, skipping auto-decoying
    /// (repeatable).
    #[arg(long = "pass-env", value_name = "VAR")]
    pass_env: Vec<String>,
    /// Disable automatic env-var decoying. Vault entries still inject decoys.
    #[arg(long)]
    pass_all_env: bool,
    /// Watch mode: for this session, destinations no rule matches are
    /// forwarded and recorded as warn events instead of blocked. The policy
    /// file is untouched; deny/escalate rules still block, and no secret is
    /// ever released by warn. The tuning posture: watch `decoyrail log -t`,
    /// add rules, return to deny.
    #[arg(long)]
    watch: bool,
    /// The command and arguments to run, after `--`.
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Store a secret and generate its decoy.
    Add(VaultAddArgs),
    /// List vault entries (decoys shown, real values redacted).
    Ls(VaultLsArgs),
    /// Remove a secret by name.
    Rm { name: String },
}

#[derive(Args)]
struct VaultLsArgs {
    /// Emit machine-readable JSON (real secrets omitted) for scripts.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VaultAddArgs {
    #[arg(long)]
    name: String,
    /// Env var to inject the decoy into for `decoyrail run`, e.g. ANTHROPIC_API_KEY.
    #[arg(long)]
    env: Option<String>,
    /// Append an allow rule to the policy releasing this secret at HOST
    /// (repeatable). Without it the secret is tripwire-only until a policy
    /// rule lists it in allow_secrets.
    #[arg(long = "allow-host", value_name = "HOST")]
    allow_hosts: Vec<String>,
    /// Where the secret rides: bearer | header:<name> | body | any.
    #[arg(long, default_value = "any")]
    location: String,
    /// The real secret value, or `-` to read from stdin. If omitted, Decoyrail
    /// prompts (hidden) on a terminal or reads a line from a pipe, keeping the
    /// secret out of shell history and `ps`.
    #[arg(long)]
    secret: Option<String>,
    // Destination flags moved into the policy (007). Kept hidden so old
    // invocations get pointed at the replacement instead of a parse error.
    #[arg(long = "host", hide = true)]
    legacy_hosts: Vec<String>,
    #[arg(long = "path-prefix", hide = true)]
    legacy_path_prefixes: Vec<String>,
    #[arg(long = "method", hide = true)]
    legacy_methods: Vec<String>,
}

#[derive(Subcommand)]
enum CaCmd {
    /// Print the path to the CA certificate.
    Path,
    /// Trust the CA in the macOS login keychain.
    Install,
    /// Remove the CA from the macOS login keychain.
    Uninstall,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print the path to the policy file.
    Path,
    /// Print the policy file, including comments.
    Show,
    /// List rules in evaluation order with 1-based positions.
    Ls(PolicyLsArgs),
    /// Show the rule, action, and secrets selected for a URL.
    Test(PolicyTestArgs),
    /// Add a rule. New rules are appended unless placed explicitly.
    Add(PolicyAddArgs),
    /// Change fields of an existing rule (by name or position).
    Set(PolicySetArgs),
    /// Delete a rule (by name or position).
    Rm(PolicyRmArgs),
    /// Move a rule to a new position (by name or position).
    Mv(PolicyMvArgs),
    /// Set the default action, or the escalate fallback with --fallback.
    Default(PolicyDefaultArgs),
    /// Remove all rules, keeping the default action.
    Flush(PolicyConfirmArgs),
    /// Restore the shipped default policy.
    Reset(PolicyConfirmArgs),
    /// Edit the policy with $EDITOR and validate it before saving.
    Edit,
    /// Bless a hand-edited policy after reviewing what changed (TTY only).
    Sign,
}

#[derive(Args)]
struct PolicyLsArgs {
    /// Emit machine-readable JSON for scripts.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct PolicyTestArgs {
    /// URL or host to evaluate (scheme optional, e.g. api.github.com/gists).
    url: String,
    /// HTTP method to test with.
    #[arg(long, default_value = "GET")]
    method: String,
}

/// Rule-shaping flags shared by `add` and `set`. On `add`, --host and --action
/// are required; on `set` every flag is optional and only what's given changes.
#[derive(Args)]
struct PolicyAddArgs {
    /// Unique rule name.
    name: String,
    /// Destination host glob, e.g. api.example.com or *.example.com (repeatable).
    #[arg(long = "host", value_name = "HOST", required = true)]
    hosts: Vec<String>,
    /// Restrict to these HTTP methods (repeatable; default any).
    #[arg(long = "method", value_name = "METHOD")]
    methods: Vec<String>,
    /// Restrict to these path prefixes (repeatable; default any).
    #[arg(long = "path-prefix", value_name = "PREFIX")]
    path_prefixes: Vec<String>,
    /// allow | deny | warn | escalate.
    #[arg(long, default_value = "allow")]
    action: String,
    /// Secret to release here: a vault name or provider:<label> (repeatable).
    #[arg(long = "allow-secret", value_name = "SECRET")]
    allow_secrets: Vec<String>,
    /// Insert at this 1-based position instead of appending.
    #[arg(long, conflicts_with_all = ["before", "after"])]
    at: Option<usize>,
    /// Insert immediately before this rule (name or position).
    #[arg(long, conflicts_with = "after")]
    before: Option<String>,
    /// Insert immediately after this rule (name or position).
    #[arg(long)]
    after: Option<String>,
}

#[derive(Args)]
struct PolicySetArgs {
    /// Rule to change (name or 1-based position).
    rule: String,
    /// Rename the rule.
    #[arg(long)]
    name: Option<String>,
    /// Replace the host list (repeatable).
    #[arg(long = "host", value_name = "HOST")]
    hosts: Vec<String>,
    /// Replace the method list (repeatable; give none to clear via --clear-methods).
    #[arg(long = "method", value_name = "METHOD")]
    methods: Vec<String>,
    /// Clear the method restriction (match any method).
    #[arg(long)]
    clear_methods: bool,
    /// Replace the path-prefix list (repeatable).
    #[arg(long = "path-prefix", value_name = "PREFIX")]
    path_prefixes: Vec<String>,
    /// Clear the path-prefix restriction (match any path).
    #[arg(long)]
    clear_path_prefixes: bool,
    /// Change the action (allow | deny | warn | escalate).
    #[arg(long)]
    action: Option<String>,
    /// Replace the released-secret list (repeatable).
    #[arg(long = "allow-secret", value_name = "SECRET")]
    allow_secrets: Vec<String>,
    /// Clear the released-secret list (release nothing here).
    #[arg(long)]
    clear_allow_secrets: bool,
}

#[derive(Args)]
struct PolicyRmArgs {
    /// Rule to delete (name or 1-based position).
    rule: String,
    /// Proceed without the confirmation prompt (required when not a TTY).
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct PolicyMvArgs {
    /// Rule to move (name or 1-based position).
    rule: String,
    /// New 1-based position.
    position: Option<usize>,
    /// Move immediately before this rule (name or position).
    #[arg(long, conflicts_with = "after")]
    before: Option<String>,
    /// Move immediately after this rule (name or position).
    #[arg(long)]
    after: Option<String>,
}

#[derive(Args)]
struct PolicyDefaultArgs {
    /// allow | deny | warn | escalate.
    action: String,
    /// Set the escalate fallback (allow | deny | warn) instead of the default
    /// action.
    #[arg(long)]
    fallback: bool,
}

#[derive(Args)]
struct PolicyConfirmArgs {
    /// Proceed without the confirmation prompt (required when not a TTY).
    #[arg(long)]
    yes: bool,
}

#[derive(Subcommand)]
enum DlpCmd {
    /// Show each detector and its mode.
    Show,
    /// Set a detector's mode.
    Set {
        /// pan | ssn | iban | aba | email | debug
        detector: String,
        /// off | warn | block | mask (for debug: on | off)
        mode: String,
    },
}

#[derive(Subcommand)]
enum LicenseCmd {
    /// Verify and install a license file offline.
    Install {
        /// Path to the license file you were sent.
        file: std::path::PathBuf,
    },
    /// Show the installed license and active tier.
    Status,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Show the active backend and key location.
    Status,
    /// Move the vault key between backends (macOS only).
    Migrate {
        /// Target backend: keychain | file.
        #[arg(long, value_name = "BACKEND")]
        to: String,
    },
}

#[derive(Args)]
struct LogArgs {
    /// Show only the last N events.
    #[arg(short = 'n', long, default_value_t = 20)]
    lines: usize,
    /// Verify the hash chain instead of printing events.
    #[arg(long)]
    verify: bool,
    /// Follow new events, like `tail -f`.
    #[arg(short = 't', long = "tail")]
    tail: bool,
    /// Show events from one process ID (`decoyrail run` prints it at launch).
    #[arg(long)]
    pid: Option<u32>,
}

#[derive(Args)]
struct StatsArgs {
    /// Time window: today | week | month | all (local time).
    #[arg(long, default_value = "today")]
    window: String,
    /// Start date (YYYY-MM-DD, local and inclusive). Overrides --window.
    #[arg(long)]
    since: Option<String>,
    /// End date (YYYY-MM-DD, local and inclusive). Defaults to today.
    #[arg(long)]
    until: Option<String>,
    /// Breakdown table to print: session | model | host | day.
    #[arg(long, default_value = "model")]
    by: String,
    /// Emit the versioned machine-readable report (see docs/stats.md).
    #[arg(long)]
    json: bool,
    /// Print today's embeddable one-line summary. Ignores window options.
    #[arg(long)]
    line: bool,
}

fn main() -> Result<()> {
    reset_sigpipe();
    let cli = Cli::parse();
    match cli.cmd {
        Command::Proxy(a) => run_proxy(a),
        Command::Run(a) => run_command(a),
        Command::Vault(c) => vault_cmd(c),
        Command::Ca(c) => ca_cmd(c),
        Command::Policy(c) => policy_cmd(c),
        Command::Dlp(c) => dlp_cmd(c),
        Command::Key(c) => key_cmd(c),
        Command::Log(a) => log_cmd(a),
        Command::Stats(a) => stats_cmd(a),
        Command::License(c) => license_cmd(c),
        Command::Status => status_cmd(),
        Command::Cache => cache_cmd(),
        Command::Budget { usd } => budget_cmd(usd),
        Command::Plan(args) => plan_cmd(args),
        Command::Uninstall(a) => uninstall_cmd(a),
    }
}

/// Rust ignores SIGPIPE by default, turning writes to a closed pipe into an
/// EPIPE that panics `println!`. Reset it to the default so `decoyrail log | head`
/// (and any piped output) terminates cleanly like a normal Unix tool.
#[cfg(unix)]
fn reset_sigpipe() {
    // Safe: setting a well-known signal to its default disposition.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

fn tokio_rt() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn run_proxy(args: ProxyArgs) -> Result<()> {
    install_crypto_provider();
    let engine = Engine::boot()?;
    tokio_rt()?.block_on(async move {
        engine.announce_session("proxy").await?;
        proxy::serve(engine, &args.addr).await
    })
}

fn run_command(args: RunArgs) -> Result<()> {
    install_crypto_provider();
    let rt = tokio_rt()?;
    rt.block_on(async move {
        let mut engine = Engine::boot()?;

        // Auto-decoy sensitive-looking terminal env vars into a session vault
        // so the child never sees them (recognized provider keys stay usable
        // via the swap; everything else becomes a pure tripwire).
        let env_secrets = if args.pass_all_env {
            Vec::new()
        } else {
            let vault = engine.vault.read().await;
            guard::detect_env(std::env::vars(), &vault, &args.pass_env)
        };

        engine.set_session_secrets(env_secrets.clone());

        if args.watch {
            engine.set_default_action_override(policy::Action::Warn);
        }

        // Label this session in the audit log with the command it launches,
        // so `decoyrail stats --by session` can say what each session was.
        engine.announce_session(&args.cmd.join(" ")).await?;

        // Bind first so we know the ephemeral port before spawning the child.
        let listener = tokio::net::TcpListener::bind(&args.addr).await?;
        let local = listener.local_addr()?;
        let proxy_engine = engine.clone();
        tokio::spawn(async move {
            proxy::serve_on(proxy_engine, listener).await;
        });

        let ca_path = config::ca_cert_path()?;
        let proxy_url = format!("http://{local}");

        // Build child env: decoys + proxy + CA trust.
        let mut child = tokio::process::Command::new(&args.cmd[0]);
        child.args(&args.cmd[1..]);
        child.env("HTTP_PROXY", &proxy_url);
        child.env("HTTPS_PROXY", &proxy_url);
        child.env("http_proxy", &proxy_url);
        child.env("https_proxy", &proxy_url);
        // An inherited NO_PROXY would punch silent holes in egress coverage.
        child.env_remove("NO_PROXY");
        child.env_remove("no_proxy");
        child.env_remove("ALL_PROXY");
        child.env_remove("all_proxy");
        child.env("NODE_EXTRA_CA_CERTS", &ca_path);
        child.env("SSL_CERT_FILE", &ca_path);
        child.env("REQUESTS_CA_BUNDLE", &ca_path);
        child.env("CURL_CA_BUNDLE", &ca_path);
        {
            let vault = engine.vault.read().await;
            for secret in &vault.secrets {
                if let Some(var) = &secret.env {
                    child.env(var, &secret.decoy);
                }
            }
        }
        for secret in &env_secrets {
            if let Some(var) = &secret.env {
                child.env(var, &secret.decoy);
            }
        }
        {
            let policy = engine.policy.read().await;
            report_session_decoys(&policy, &env_secrets);
        }

        if args.watch {
            eprintln!(
                "decoyrail: WATCH MODE for this session: destinations no rule matches are \
                 FORWARDED and logged as warn events, not blocked."
            );
            eprintln!(
                "decoyrail: deny and escalate rules still block, and warn never releases a \
                 secret. Watch unknown egress with `decoyrail log -t`, add the rules you \
                 decide on, then run without --watch to return to deny."
            );
        }

        eprintln!(
            "decoyrail: launched `{}` behind proxy {} (decoys injected, real secrets released only by policy; \
             this session in the log: decoyrail log --pid {})",
            args.cmd.join(" "),
            proxy_url,
            std::process::id()
        );
        let status = child.status().await.context("spawning child process")?;
        std::process::exit(status.code().unwrap_or(1));
    })
}

/// Tell the user which env vars were auto-decoyed, and whether each stays
/// usable (a policy rule releases it) or is a pure tripwire.
fn report_session_decoys(policy: &policy::Policy, secrets: &[vault::Secret]) {
    if secrets.is_empty() {
        return;
    }
    eprintln!(
        "decoyrail: auto-decoyed {} env var(s) for this session:",
        secrets.len()
    );
    for s in secrets {
        let Some(var) = &s.env else { continue };
        let rules = policy.releasing_rules(s);
        if rules.is_empty() {
            eprintln!(
                "  {var}  tripwire-only (release it via allow_secrets in the policy to keep it usable)"
            );
        } else {
            let hosts: Vec<&str> = rules
                .iter()
                .flat_map(|r| r.hosts.iter().map(String::as_str))
                .collect();
            eprintln!("  {var}  usable at {}", hosts.join(", "));
        }
    }
    eprintln!("  (skip one with --pass-env VAR, or all with --pass-all-env)");
}

fn vault_cmd(cmd: VaultCmd) -> Result<()> {
    let mut vault = Vault::load_or_init()?;
    match cmd {
        VaultCmd::Add(a) => {
            if !a.legacy_hosts.is_empty()
                || !a.legacy_path_prefixes.is_empty()
                || !a.legacy_methods.is_empty()
            {
                return Err(anyhow!(
                    "--host/--path-prefix/--method moved into the policy: a rule's \
                     allow_secrets now decides where a secret is released.\n\
                     Use `--allow-host {0}` to append an allow rule releasing '{1}', \
                     or edit {2} (add allow_secrets = [\"{1}\"] to a rule).",
                    a.legacy_hosts
                        .first()
                        .map(String::as_str)
                        .unwrap_or("<host>"),
                    a.name,
                    config::policy_path()?.display()
                ));
            }
            let real = read_secret(a.secret)?;
            if real.is_empty() {
                return Err(anyhow!("empty secret"));
            }
            let location = parse_location(&a.location)?;
            let decoy = vault.add(&a.name, &real, a.env.clone(), location)?;
            println!("Added '{}'. Decoy issued:\n  {}", a.name, decoy);
            if let Some(v) = &a.env {
                println!("`decoyrail run` will export {v}=<decoy> to the child.");
            }
            if !a.allow_hosts.is_empty() {
                append_release_rule(&a.name, &a.allow_hosts)?;
            }
            report_release_status(&vault, &a.name)?;
        }
        VaultCmd::Ls(a) => {
            let policy = policy::Policy::load_or_default()?;
            if a.json {
                // Machine-readable, real secrets omitted. Scripts (and e2e)
                // consume this instead of scraping the human table.
                let items: Vec<_> = vault
                    .secrets
                    .iter()
                    .map(|s| {
                        let released_by: Vec<&str> = policy
                            .releasing_rules(s)
                            .iter()
                            .map(|r| r.name.as_str())
                            .collect();
                        serde_json::json!({
                            "name": s.name,
                            "env": s.env,
                            "decoy": s.decoy,
                            "location": s.location,
                            "provider": s.provider,
                            "released_by": released_by,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                if vault.secrets.is_empty() {
                    println!("(vault is empty)");
                }
                for s in &vault.secrets {
                    let rules = policy.releasing_rules(s);
                    let release = if rules.is_empty() {
                        "tripwire-only".to_string()
                    } else {
                        let hosts: Vec<&str> = rules
                            .iter()
                            .flat_map(|r| r.hosts.iter().map(String::as_str))
                            .collect();
                        format!("released at {}", hosts.join(", "))
                    };
                    println!(
                        "{:<16} env={:<22} loc={:?} {release}\n    real={}  decoy={}",
                        s.name,
                        s.env.clone().unwrap_or_else(|| "-".into()),
                        s.location,
                        redact(&s.real),
                        s.decoy,
                    );
                }
            }
        }
        VaultCmd::Rm { name } => {
            vault.remove(&name)?;
            println!("Removed '{name}'.");
        }
    }
    Ok(())
}

/// Append an allow rule releasing `name` at `hosts` to the policy file,
/// validating that the result still parses before writing. Appending (not
/// prepending) preserves carve-outs above; if a broader earlier rule shadows
/// the new one, the lint printed by `report_release_status` says so.
fn append_release_rule(name: &str, hosts: &[String]) -> Result<()> {
    let _ = policy::Policy::load_or_default()?; // materialize the default first
    let path = config::policy_path()?;
    let mut text = std::fs::read_to_string(&path)?;
    let hosts_toml = hosts
        .iter()
        .map(|h| format!("\"{h}\""))
        .collect::<Vec<_>>()
        .join(", ");
    text.push_str(&format!(
        "\n# Added by `decoyrail vault add --name {name}`.\n\
         [[rule]]\nname = \"{name}\"\nhosts = [{hosts_toml}]\n\
         action = \"allow\"\nallow_secrets = [\"{name}\"]\n"
    ));
    let _: policy::Policy =
        toml::from_str(&text).context("appending the rule would break policy.toml; not written")?;
    decoyrail::policy_edit::write_policy(&text, "vault add --allow-host")?;
    println!("Policy rule '{name}' appended to {}.", path.display());
    Ok(())
}

/// After an add: say where the secret is actually released (or that it is
/// tripwire-only), and surface any policy lint warnings.
fn report_release_status(vault: &Vault, name: &str) -> Result<()> {
    let policy = policy::Policy::load_or_default()?;
    let secret = vault
        .secrets
        .iter()
        .find(|s| s.name == name)
        .expect("just added");
    let rules = policy.releasing_rules(secret);
    if rules.is_empty() {
        println!(
            "Tripwire-only: no policy rule releases '{name}' yet. Any use of the \
             decoy will be blocked and alerted. To make it usable, re-run with \
             --allow-host <host>, or add allow_secrets = [\"{name}\"] to a rule in {}.",
            config::policy_path()?.display()
        );
    } else {
        for r in &rules {
            println!("Released by rule '{}' at {}.", r.name, r.hosts.join(", "));
        }
    }
    for w in policy.lint(&vault.secrets) {
        eprintln!("decoyrail: policy warning: {w}");
    }
    Ok(())
}

/// Resolve the real secret from the `--secret` argument, a hidden prompt, or
/// stdin — preferring paths that keep it out of shell history and `ps`.
fn read_secret(arg: Option<String>) -> Result<String> {
    use std::io::IsTerminal;
    match arg {
        // Explicit inline value: usable, but visible to other processes.
        Some(s) if s != "-" => {
            eprintln!(
                "decoyrail: warning: passing --secret on the command line exposes it in shell \
                 history and `ps`; omit --secret to be prompted, or pass `-` to pipe via stdin"
            );
            Ok(s)
        }
        // `-` always means stdin.
        Some(_) => read_stdin_secret(),
        // Omitted: prompt hidden on a TTY, else read a piped line.
        None => {
            if std::io::stdin().is_terminal() {
                Ok(rpassword::prompt_password("Real secret (hidden): ")?
                    .trim()
                    .to_string())
            } else {
                read_stdin_secret()
            }
        }
    }
}

fn read_stdin_secret() -> Result<String> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn parse_location(s: &str) -> Result<Location> {
    let lower = s.to_lowercase();
    Ok(match lower.as_str() {
        "bearer" => Location::Bearer,
        "body" => Location::Body,
        "any" => Location::Any,
        other => {
            if let Some(name) = other.strip_prefix("header:") {
                Location::Header(name.to_string())
            } else {
                return Err(anyhow!(
                    "bad --location '{s}' (use bearer|header:<name>|body|any)"
                ));
            }
        }
    })
}

fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return "•".repeat(n);
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s
        .chars()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail} ({n} chars)")
}

fn ca_cmd(cmd: CaCmd) -> Result<()> {
    // Uninstall must never mint a fresh CA just to have something to delete.
    if matches!(cmd, CaCmd::Uninstall) {
        return ca_uninstall();
    }
    // Ensure a CA exists.
    let _ = ca::CertAuthority::load_or_create()?;
    let path = config::ca_cert_path()?;
    match cmd {
        CaCmd::Uninstall => unreachable!("handled above"),
        CaCmd::Path => println!("{}", path.display()),
        CaCmd::Install => {
            #[cfg(target_os = "macos")]
            {
                let status = std::process::Command::new("security")
                    .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
                    .arg(login_keychain()?)
                    .arg(&path)
                    .status()
                    .context("running `security add-trusted-cert`")?;
                if status.success() {
                    println!("Installed Decoyrail CA into the login keychain as trusted.");
                } else {
                    return Err(anyhow!(
                        "keychain install failed; run manually:\n  security add-trusted-cert -r trustRoot {}",
                        path.display()
                    ));
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                println!(
                    "CA is at {}. Add it to your trust store to enable interception.",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Remove the trust root `ca install` added. Deletes by SHA-1 fingerprint,
/// never by display name, so an unrelated certificate that happens to be
/// called "Decoyrail Device CA" cannot be touched. An absent cert file or an
/// absent keychain entry is success, not an error: uninstall is repeatable.
fn ca_uninstall() -> Result<()> {
    let Some(fp) = ca::root_sha1_fingerprint()? else {
        println!(
            "No CA material at {}; nothing identifiable to remove.",
            config::ca_cert_path()?.display()
        );
        println!(
            "If a 'Decoyrail Device CA' is still trusted (state dir deleted first?), check its \
             fingerprint in Keychain Access and remove it there."
        );
        return Ok(());
    };
    #[cfg(target_os = "macos")]
    {
        let keychain = login_keychain()?;
        // Presence check first: `delete-certificate` exits 1 with the same
        // message for "not found" and for real failures, so it can't be the
        // signal that a repeat uninstall is fine.
        let installed = |fp: &str| -> Result<bool> {
            let out = std::process::Command::new("security")
                .args(["find-certificate", "-a", "-Z"])
                .arg(&keychain)
                .output()
                .context("running `security find-certificate`")?;
            Ok(String::from_utf8_lossy(&out.stdout).contains(fp))
        };
        let mut removed = 0u32;
        // `add-trusted-cert` dedupes identical certs, but bound a loop anyway
        // in case several copies ended up in the keychain over time.
        while removed < 8 && installed(&fp)? {
            // -t also drops the user trust settings the install created. Some
            // macOS versions reject -t when no trust settings exist, so a
            // failed -t pass retries without it before giving up.
            let with_t = std::process::Command::new("security")
                .args(["delete-certificate", "-Z", &fp, "-t"])
                .arg(&keychain)
                .output()
                .context("running `security delete-certificate`")?;
            if with_t.status.success() {
                removed += 1;
                continue;
            }
            let without_t = std::process::Command::new("security")
                .args(["delete-certificate", "-Z", &fp])
                .arg(&keychain)
                .output()
                .context("running `security delete-certificate`")?;
            if !without_t.status.success() {
                let msg = String::from_utf8_lossy(&without_t.stderr)
                    .trim()
                    .to_string();
                return Err(anyhow!(
                    "keychain removal failed; run manually:\n  \
                     security delete-certificate -Z {fp} -t {keychain}\n{msg}"
                ));
            }
            removed += 1;
        }
        if removed > 0 {
            println!("Removed the Decoyrail CA (SHA-1 {fp}) from the login keychain.");
        } else {
            println!("No Decoyrail CA (SHA-1 {fp}) in the login keychain; nothing to remove.");
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        println!(
            "Remove the CA with SHA-1 fingerprint {fp} from the trust store you added it to \
             (the cert file is {}).",
            config::ca_cert_path()?.display()
        );
    }
    Ok(())
}

/// `decoyrail uninstall`: everything the product put on this machine, in the
/// order that keeps each step identifiable: trust root first (the cert file
/// is its identity), then the keychain key item (bound to the still-existing
/// home path), then the state directory itself.
fn uninstall_cmd(a: UninstallArgs) -> Result<()> {
    let home = config::home()?;
    if !confirm(
        &format!(
            "Remove Decoyrail from this machine? This deletes the trusted CA and everything \
             under {}: the vault (your real secrets), policy, and audit log.",
            home.display()
        ),
        a.yes,
    )? {
        println!("Nothing removed.");
        return Ok(());
    }

    ca_uninstall()?;

    // The vault-key keychain item exists only for the default home; it is
    // keyed by the canonicalized home path, so it must go before the dir does.
    #[cfg(target_os = "macos")]
    if config::is_default_home() && home.exists() {
        let bound = config::canonical_home()?;
        match decoyrail::keyring::delete(&bound.to_string_lossy()) {
            Ok(true) => println!(
                "Removed the vault-key keychain item ({}).",
                decoyrail::keyring::SERVICE
            ),
            Ok(false) => {}
            Err(e) => eprintln!("decoyrail: warning: keychain item not removed: {e:#}"),
        }
    }

    if home.exists() {
        std::fs::remove_dir_all(&home).with_context(|| format!("removing {}", home.display()))?;
        println!("Removed {}.", home.display());
    } else {
        println!("{} already absent.", home.display());
    }

    println!("\nStill yours to remove:");
    match std::env::current_exe() {
        Ok(exe) => println!("  - the binary itself: rm {}", exe.display()),
        Err(_) => println!("  - the binary itself (wherever you installed it)"),
    }
    println!("  - any PATH line your shell profile added for it");
    println!(
        "  - shells still inside `decoyrail run` (exit them; their proxy env now points at nothing)"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn login_keychain() -> Result<String> {
    let home = dirs::home_dir().context("home dir")?;
    Ok(home
        .join("Library/Keychains/login.keychain-db")
        .to_string_lossy()
        .into_owned())
}

fn policy_cmd(cmd: PolicyCmd) -> Result<()> {
    use decoyrail::policy_edit::{Anchor, PolicyDoc, RuleEdit};

    match cmd {
        PolicyCmd::Path => {
            policy::Policy::load_or_default()?; // materialize default on first run
            println!("{}", config::policy_path()?.display());
        }
        PolicyCmd::Show => {
            policy::Policy::load_or_default()?;
            println!("{}", std::fs::read_to_string(config::policy_path()?)?);
            print_policy_lint()?;
        }
        PolicyCmd::Ls(a) => policy_ls(a.json)?,
        PolicyCmd::Test(a) => policy_test(&a.url, &a.method)?,
        PolicyCmd::Add(a) => {
            let anchor = match (a.at, a.before, a.after) {
                (Some(pos), _, _) => Anchor::At(pos),
                (_, Some(b), _) => Anchor::Before(b),
                (_, _, Some(af)) => Anchor::After(af),
                _ => Anchor::End,
            };
            let edit = RuleEdit {
                name: Some(a.name.clone()),
                hosts: Some(a.hosts),
                methods: Some(a.methods),
                path_prefixes: Some(a.path_prefixes),
                action: Some(a.action),
                allow_secrets: Some(a.allow_secrets),
            };
            let mut doc = PolicyDoc::load()?;
            doc.add(&edit, &anchor)?;
            doc.save("policy add")?;
            println!("Added rule '{}'.", a.name);
            after_policy_mutation()?;
        }
        PolicyCmd::Set(a) => {
            let edit = RuleEdit {
                name: a.name,
                hosts: opt_list(a.hosts),
                methods: list_or_clear(a.methods, a.clear_methods),
                path_prefixes: list_or_clear(a.path_prefixes, a.clear_path_prefixes),
                action: a.action,
                allow_secrets: list_or_clear(a.allow_secrets, a.clear_allow_secrets),
            };
            let mut doc = PolicyDoc::load()?;
            let name = doc.set(&a.rule, &edit)?;
            doc.save("policy set")?;
            println!("Updated rule '{name}'.");
            after_policy_mutation()?;
        }
        PolicyCmd::Rm(a) => {
            let mut doc = PolicyDoc::load()?;
            // Remove first (so an unknown rule errors before we prompt), then
            // confirm before the write actually lands.
            let name = doc.remove(&a.rule)?;
            if !confirm(&format!("Delete rule '{name}' from the policy?"), a.yes)? {
                println!("Aborted; policy unchanged.");
                return Ok(());
            }
            let backup = doc.save("policy rm")?;
            println!("Removed rule '{name}'. Backup at {}.", backup.display());
            after_policy_mutation()?;
        }
        PolicyCmd::Mv(a) => {
            let anchor = match (a.position, a.before, a.after) {
                (Some(pos), _, _) => Anchor::At(pos),
                (_, Some(b), _) => Anchor::Before(b),
                (_, _, Some(af)) => Anchor::After(af),
                _ => {
                    return Err(anyhow!(
                        "say where to move '{}': a position, or --before/--after a rule",
                        a.rule
                    ))
                }
            };
            let mut doc = PolicyDoc::load()?;
            let name = doc.move_rule(&a.rule, &anchor)?;
            doc.save("policy mv")?;
            println!("Moved rule '{name}'.");
            after_policy_mutation()?;
        }
        PolicyCmd::Default(a) => {
            let mut doc = PolicyDoc::load()?;
            if a.fallback {
                doc.set_escalate_fallback(&a.action)?;
                doc.save("policy default --fallback")?;
                println!("Escalate fallback set to {}.", a.action.to_lowercase());
            } else {
                doc.set_default(&a.action)?;
                doc.save("policy default")?;
                println!("Default action set to {}.", a.action.to_lowercase());
                if matches!(policy::Action::parse(&a.action), Ok(policy::Action::Warn)) {
                    println!(
                        "Unmatched destinations are now forwarded and recorded as warn \
                         events, not blocked. Watch them with `decoyrail log -t`; for a \
                         single session, `decoyrail run --watch` does this without \
                         editing the policy."
                    );
                }
            }
            after_policy_mutation()?;
        }
        PolicyCmd::Flush(a) => {
            let mut doc = PolicyDoc::load()?;
            let default = policy::Policy::load_or_default()?.default_action;
            if !confirm(
                &format!(
                    "Remove all {} rule(s)? The default action ({}) then applies to everything.",
                    doc.len(),
                    default.as_str()
                ),
                a.yes,
            )? {
                println!("Aborted; policy unchanged.");
                return Ok(());
            }
            doc.flush();
            let backup = doc.save("policy flush")?;
            println!("Flushed all rules. Backup at {}.", backup.display());
            if matches!(default, policy::Action::Deny) {
                println!(
                    "Default is deny: every destination is now blocked, including the \
                     agent's own provider. Add rules back with `decoyrail policy add`."
                );
            }
            after_policy_mutation()?;
        }
        PolicyCmd::Reset(a) => {
            if !confirm("Overwrite the policy with the shipped defaults?", a.yes)? {
                println!("Aborted; policy unchanged.");
                return Ok(());
            }
            // The unchecked install on purpose: reset is the recovery path
            // out of an untrusted or deleted policy, and what it writes is
            // the shipped default, not anything derived from the file.
            let backup =
                decoyrail::integrity::install(policy::DEFAULT_POLICY_TOML, "policy reset")?;
            if backup.exists() {
                println!(
                    "Policy reset to the shipped defaults. Previous policy backed up at {}.",
                    backup.display()
                );
            } else {
                println!("Policy reset to the shipped defaults.");
            }
            after_policy_mutation()?;
        }
        PolicyCmd::Edit => policy_edit()?,
        PolicyCmd::Sign => policy_sign()?,
    }
    Ok(())
}

/// `decoyrail policy sign`: bless a hand-edited policy. Shows what changed
/// against the last trusted version, asks for confirmation on a TTY, and
/// refuses to run without one; scripting around the review on purpose is
/// the user's choice to make interactively, not a flag.
fn policy_sign() -> Result<()> {
    use decoyrail::integrity::{self, Verdict};
    use std::io::IsTerminal;

    // Materializes a trusted default on a fresh home, and refuses broken
    // TOML before anything else: blessing a typo would turn it into a
    // deny-all surprise at the next restart.
    policy::Policy::load_or_default()?;
    let path = config::policy_path()?;
    let text = std::fs::read_to_string(&path)?;
    if integrity::verify(&text)? == Verdict::Trusted {
        println!("Policy already trusted; nothing to bless.");
        return Ok(());
    }
    match integrity::baseline()? {
        Some((old, at)) => {
            let changes = integrity::diff(&old, &text);
            if changes.is_empty() {
                println!("No line-level changes since the last blessing ({at}); the files differ only in bytes lines don't show (line endings, a trailing newline).");
            } else {
                println!("Changes since the last blessed policy ({at}):");
                for line in &changes {
                    println!("  {line}");
                }
            }
        }
        None => println!(
            "No trusted baseline to diff against; review {} in full before confirming.",
            path.display()
        ),
    }
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "refusing to bless without a terminal: `decoyrail policy sign` wants \
             a human to review the changes above and confirm interactively"
        ));
    }
    eprint!("Bless this policy for this machine? [y/N] ");
    use std::io::Write as _;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        println!("Aborted; nothing blessed.");
        return Ok(());
    }
    let fp = integrity::bless_current()?;
    println!("Policy blessed (sha256={fp}). A running proxy picks it up on the next request.");
    Ok(())
}

/// A repeatable-flag list: empty means "not given" for `set`.
fn opt_list(v: Vec<String>) -> Option<Vec<String>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Resolve a list flag with its explicit --clear-* companion into an edit:
/// values given → replace; --clear given → empty (remove); neither → unchanged.
fn list_or_clear(v: Vec<String>, clear: bool) -> Option<Vec<String>> {
    if clear {
        Some(Vec::new())
    } else {
        opt_list(v)
    }
}

/// Confirm a destructive action: honored automatically with --yes; on a TTY,
/// prompt; otherwise refuse (so scripts must opt in explicitly).
fn confirm(prompt: &str, yes: bool) -> Result<bool> {
    use std::io::IsTerminal;
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "{prompt}\nrefusing without a terminal to confirm; pass --yes to proceed"
        ));
    }
    eprint!("{prompt} [y/N] ");
    use std::io::Write as _;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// After a policy write: surface lint warnings, exactly as a hot-reload would.
fn after_policy_mutation() -> Result<()> {
    print_policy_lint()
}

fn print_policy_lint() -> Result<()> {
    let policy = policy::Policy::load_or_default()?;
    let vault = Vault::load_or_init()?;
    for w in policy.lint(&vault.secrets) {
        eprintln!("decoyrail: policy warning: {w}");
    }
    Ok(())
}

/// `decoyrail policy ls`: rules in evaluation order with positions, then the
/// default action and escalate fallback.
fn policy_ls(json: bool) -> Result<()> {
    let policy = policy::Policy::load_or_default()?;
    // Whether the file on disk is currently trusted, so "will my next
    // restart work" is answerable without restarting.
    let trusted = {
        let text = std::fs::read_to_string(config::policy_path()?)?;
        decoyrail::integrity::verify(&text)? == decoyrail::integrity::Verdict::Trusted
    };
    if json {
        let rules: Vec<_> = policy
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                serde_json::json!({
                    "position": i + 1,
                    "name": r.name,
                    "action": r.action.as_str(),
                    "hosts": r.hosts,
                    "methods": r.methods,
                    "path_prefixes": r.path_prefixes,
                    "allow_secrets": r.allow_secrets,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "default_action": policy.default_action.as_str(),
                "escalate_fallback": policy.escalate_fallback.as_str(),
                "trusted": trusted,
                "rules": rules,
            }))?
        );
        return Ok(());
    }
    if policy.rules.is_empty() {
        println!("(no rules; the default action applies to everything)");
    }
    for (i, r) in policy.rules.iter().enumerate() {
        println!(
            "{:>3}  {:<8}  {:<22}  {}",
            i + 1,
            r.action.as_str(),
            r.name,
            r.hosts.join(", ")
        );
        let mut extra = Vec::new();
        if !r.methods.is_empty() {
            extra.push(format!("methods: {}", r.methods.join(", ")));
        }
        if !r.path_prefixes.is_empty() {
            extra.push(format!("paths: {}", r.path_prefixes.join(", ")));
        }
        if !r.allow_secrets.is_empty() {
            extra.push(format!("releases: {}", r.allow_secrets.join(", ")));
        }
        if !extra.is_empty() {
            println!("     {}", extra.join("  |  "));
        }
    }
    println!(
        "default: {}   escalate -> {}",
        policy.default_action.as_str(),
        policy.escalate_fallback.as_str()
    );
    if trusted {
        println!("integrity: trusted (the proxy loads this file)");
    } else {
        println!(
            "integrity: NOT TRUSTED. The file was changed outside decoyrail; the proxy \
             will not load it. Review it, then run `decoyrail policy sign`."
        );
    }
    print_policy_lint()?;
    Ok(())
}

/// `decoyrail policy test <url>`: evaluate the live policy exactly as the proxy
/// would, and report the winning rule, the resolved action, and which vault
/// secrets that rule would release there. Changes nothing.
fn policy_test(url: &str, method: &str) -> Result<()> {
    let (host, path) = split_url(url);
    let method = method.to_ascii_uppercase();
    let policy = policy::Policy::load_or_default()?;
    let d = policy.evaluate(&host, &path, &method);

    println!("{method} {host}{path}");
    println!("  rule:   {}", d.rule);
    if d.escalated {
        println!(
            "  action: {} (escalated; fallback {})",
            d.action.as_str(),
            policy.escalate_fallback.as_str()
        );
    } else {
        println!("  action: {}", d.action.as_str());
    }
    if d.allow_secrets.is_empty() {
        println!("  secrets: rule releases nothing here");
    } else {
        // Which of the vault's secrets this decision would actually release
        // (an allow rule that lists them). Provider labels are reported as
        // listed even without a matching vault entry.
        let vault = Vault::load_or_init()?;
        let released: Vec<&str> = vault
            .secrets
            .iter()
            .filter(|s| d.releases(s))
            .map(|s| s.name.as_str())
            .collect();
        if d.action == policy::Action::Allow {
            if released.is_empty() {
                println!(
                    "  secrets: rule lists [{}]; no matching vault secret to release",
                    d.allow_secrets.join(", ")
                );
            } else {
                println!(
                    "  secrets: releases {} (rule lists [{}])",
                    released.join(", "),
                    d.allow_secrets.join(", ")
                );
            }
        } else {
            println!(
                "  secrets: rule lists [{}]; not released because the action is {}",
                d.allow_secrets.join(", "),
                d.action.as_str()
            );
        }
    }
    Ok(())
}

/// Split a URL or bare host into (host, path). Scheme, userinfo, and port are
/// stripped; a missing path becomes "/". Host is lowercased to match the proxy.
fn split_url(input: &str) -> (String, String) {
    let after_scheme = input.split_once("://").map(|(_, r)| r).unwrap_or(input);
    let (hostport, path) = match after_scheme.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (after_scheme, "/".to_string()),
    };
    // Strip userinfo, then the port.
    let host = hostport
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(hostport);
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    (host.to_ascii_lowercase(), path)
}

/// `decoyrail policy edit`: open the policy in $EDITOR against a scratch copy,
/// validate the result parses, and only then replace the live file (like
/// visudo). A broken edit is rejected and the live policy is left in place.
fn policy_edit() -> Result<()> {
    policy::Policy::load_or_default()?; // materialize the default first
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .map_err(|_| {
            anyhow!("$EDITOR is not set; set it to your editor (e.g. `EDITOR=vim decoyrail policy edit`)")
        })?;
    let path = config::policy_path()?;
    let scratch = path.with_extension("toml.edit");
    std::fs::copy(&path, &scratch).with_context(|| format!("preparing {}", scratch.display()))?;

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"{}\"", scratch.display()))
        .status()
        .with_context(|| format!("launching editor `{editor}`"));

    let result = (|| -> Result<()> {
        status?;
        let edited = std::fs::read_to_string(&scratch)?;
        if edited == std::fs::read_to_string(&path)? {
            println!("No changes; policy left as is.");
            return Ok(());
        }
        // Validate before it replaces the live file; on a parse error the live
        // policy stays put.
        decoyrail::policy_edit::write_policy(&edited, "policy edit")
            .context("edited policy rejected; the live policy is unchanged")?;
        println!("Policy updated.");
        after_policy_mutation()?;
        Ok(())
    })();

    // Always clean up the scratch file, whatever happened.
    let _ = std::fs::remove_file(&scratch);
    result
}

fn dlp_cmd(cmd: DlpCmd) -> Result<()> {
    use decoyrail::detect::{mode_for, Detector};
    let current = policy::Policy::load_or_default()?;
    match cmd {
        DlpCmd::Show => {
            println!("Sensitive-data filtering (block rejects, mask replaces with a placeholder,");
            println!("warn forwards but records an alert, off disables):");
            for d in Detector::ALL {
                println!(
                    "  {:<6} {:<6} {}",
                    d.name(),
                    mode_for(&current.dlp, d).name(),
                    d.describe()
                );
            }
            if current.dlp.debug {
                println!(
                    "  debug  on     hits dump the payload to {}",
                    config::dlp_debug_dir()?.display()
                );
            }
            println!("Change with `decoyrail dlp set <detector> <mode>`.");
        }
        DlpCmd::Set { detector, mode } => {
            let detector = detector.to_lowercase();
            let mode = mode.to_lowercase();
            // `debug` sits alongside the detectors: on|off, and a hit dumps
            // the request (secrets scrubbed) to a file for inspection.
            let value = if detector == "debug" {
                match mode.as_str() {
                    "on" | "true" => toml_edit::value(true),
                    "off" | "false" => toml_edit::value(false),
                    _ => return Err(anyhow!("bad mode '{mode}' for debug (use on|off)")),
                }
            } else {
                if !Detector::ALL.iter().any(|d| d.name() == detector) {
                    return Err(anyhow!(
                        "unknown detector '{detector}' (use pan|ssn|iban|aba|email|debug)"
                    ));
                }
                if !["off", "warn", "block", "mask"].contains(&mode.as_str()) {
                    return Err(anyhow!("bad mode '{mode}' (use off|warn|block|mask)"));
                }
                toml_edit::value(mode.clone())
            };
            // Edit in place, preserving the user's comments and rule layout;
            // write_policy validates the result and leaves it trusted.
            let path = config::policy_path()?;
            let text = std::fs::read_to_string(&path)?;
            let mut doc = text
                .parse::<toml_edit::DocumentMut>()
                .context("parsing policy.toml")?;
            doc["dlp"][detector.as_str()] = value;
            let edited = doc.to_string();
            decoyrail::policy_edit::write_policy(&edited, "dlp set")?;
            println!("Set {detector} = {mode}. A running proxy picks it up on the next request.");
            if detector == "debug" && matches!(mode.as_str(), "on" | "true") {
                println!(
                    "Requests with DLP hits now dump their full payload (real secrets \
                     scrubbed) to {}.",
                    config::dlp_debug_dir()?.display()
                );
                println!("Dump files can hold sensitive data; turn debug off when done.");
            }
        }
    }
    Ok(())
}

fn key_cmd(cmd: KeyCmd) -> Result<()> {
    match cmd {
        KeyCmd::Status => key_status(),
        KeyCmd::Migrate { to } => key_migrate(&to.to_lowercase()),
    }
}

fn key_status() -> Result<()> {
    let home = config::ensure_home()?;
    let default = config::is_default_home();
    println!(
        "Backend: {}",
        match vault::resolve_backend()? {
            vault::KeyBackend::File => "file (vault.key on disk)",
            vault::KeyBackend::Keychain => "keychain (login-keychain item, this binary only)",
        }
    );
    println!(
        "Home: {}{}",
        home.display(),
        if default {
            ""
        } else {
            " (override; the keychain is never consulted for a non-default home)"
        }
    );
    println!(
        "vault.key file: {}",
        if config::vault_key_path()?.exists() {
            "present"
        } else {
            "absent"
        }
    );
    if cfg!(not(target_os = "macos")) {
        println!("Keychain item: (keychain backend unsupported on this platform)");
    } else if !default {
        println!("Keychain item: not consulted (non-default home)");
    } else {
        #[cfg(target_os = "macos")]
        {
            let bound = config::canonical_home()?;
            if decoyrail::keyring::exists(&bound.to_string_lossy())? {
                println!(
                    "Keychain item ({}): present, bound to {}",
                    decoyrail::keyring::SERVICE,
                    bound.display()
                );
            } else {
                println!(
                    "Keychain item ({}): absent, using the vault.key file \
                     (release installs start on the keychain; move an \
                     existing key in with `decoyrail key migrate --to keychain`)",
                    decoyrail::keyring::SERVICE
                );
            }
        }
    }
    Ok(())
}

fn key_migrate(to: &str) -> Result<()> {
    if !matches!(to, "keychain" | "file") {
        return Err(anyhow!("bad --to '{to}' (use keychain|file)"));
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(anyhow!(
            "the keychain backend is only supported on macOS; the vault key stays at {}",
            config::vault_key_path()?.display()
        ))
    }
    #[cfg(target_os = "macos")]
    {
        if !config::is_default_home() {
            return Err(anyhow!(
                "key migration only runs against the default home ({}); unset DECOYRAIL_HOME.\n\
                 The restriction is the point: the keychain key must be reachable only from \
                 the genuine home, which is what enforces the genuine policy.",
                config::default_home()?.display()
            ));
        }
        let bound = config::canonical_home()?;
        let store = vault::OsKeyStore::new(bound.to_string_lossy().into_owned());
        match to {
            "keychain" => {
                if vault::migrate_key_to_store(&store)? {
                    audit_key_event(format!(
                        "vault key moved to the login keychain, bound to {}",
                        bound.display()
                    ))?;
                    println!(
                        "Vault key moved to the login keychain, bound to {}.",
                        bound.display()
                    );
                    println!(
                        "vault.key has been removed. Only this binary reads the item silently; \
                         any other process triggers the macOS consent prompt. An unexpected \
                         prompt for '{}' is itself a tripwire: something else wants your key.",
                        decoyrail::keyring::SERVICE
                    );
                } else {
                    println!("Already on the keychain backend; nothing to migrate.");
                }
            }
            _ => {
                if vault::migrate_key_to_file(&store)? {
                    audit_key_event("vault key moved back to the on-disk file".to_string())?;
                    println!(
                        "Vault key restored to {} and the keychain item removed.",
                        config::vault_key_path()?.display()
                    );
                } else {
                    println!("Already on the file backend; nothing to migrate.");
                }
            }
        }
        Ok(())
    }
}

/// Record a key-backend migration in the audit log: direction and backend
/// only, never key material.
#[cfg(target_os = "macos")]
fn audit_key_event(note: String) -> Result<()> {
    let entry = audit::Entry {
        host: "-".into(),
        path: "-".into(),
        method: "-".into(),
        action: "key_migrate".into(),
        note,
        ..Default::default()
    };
    audit::Auditor::open()?.append(entry, util::now_rfc3339())?;
    Ok(())
}

fn log_cmd(args: LogArgs) -> Result<()> {
    if args.verify {
        let n = audit::verify()?;
        println!("audit chain OK: {n} events verified");
        return Ok(());
    }
    let path = config::audit_path()?;
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    // Filter by pid before applying -n, so `--pid X -n 20` means "the last 20
    // events of session X", not "session X's share of the last 20 events".
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| matches_pid(l, args.pid))
        .collect();
    let start = lines.len().saturating_sub(args.lines);
    for line in &lines[start..] {
        print_audit_line(line);
    }
    if !args.tail {
        return Ok(());
    }

    // Follow mode: the audit log is append-only, so polling the length and
    // reading from the last-seen byte offset is enough. A shrink means the
    // file was replaced (fresh DECOYRAIL_HOME, manual reset) — start over.
    use std::io::{Read as _, Seek as _};
    let mut offset = text.len() as u64;
    let mut pending = String::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
            pending.clear();
        }
        if len == offset {
            continue;
        }
        let mut f = std::fs::File::open(&path)?;
        f.seek(std::io::SeekFrom::Start(offset))?;
        let mut chunk = String::new();
        f.read_to_string(&mut chunk)?;
        offset += chunk.len() as u64;
        pending.push_str(&chunk);
        // Print only complete lines; a partially flushed event stays buffered
        // until its newline arrives.
        while let Some(nl) = pending.find('\n') {
            let line: String = pending.drain(..=nl).collect();
            let line = line.trim();
            if !line.is_empty() && matches_pid(line, args.pid) {
                print_audit_line(line);
            }
        }
    }
}

fn matches_pid(line: &str, pid: Option<u32>) -> bool {
    let Some(pid) = pid else { return true };
    serde_json::from_str::<audit::AuditEvent>(line)
        .map(|ev| ev.pid == pid)
        .unwrap_or(false)
}

fn print_audit_line(line: &str) {
    let Ok(ev) = serde_json::from_str::<audit::AuditEvent>(line) else {
        return;
    };
    // A rejected policy load is the same class of news as a honeytoken
    // alarm: someone or something edited the release gate out-of-band.
    let flag = if ev.action == "tamper" {
        "[TAMP]"
    } else if !ev.tripwires.is_empty() {
        "[TRIP]"
    } else if ev.action == "deny" {
        "[DENY]"
    } else if ev.action == "warn" {
        "[WARN]"
    } else if ev.action == "alert" {
        "[ALRT]"
    } else {
        "[ ok ]"
    };
    println!(
        "{flag} {} pid={:<6} {:<6} {}{}  [{}] {}",
        ev.ts, ev.pid, ev.method, ev.host, ev.path, ev.rule, ev.note
    );
    if !ev.swaps.is_empty() {
        println!("        swapped: {}", ev.swaps.join(", "));
    }
    if !ev.tripwires.is_empty() {
        println!("        TRIPWIRE: {}", ev.tripwires.join(", "));
    }
}

fn stats_cmd(args: StatsArgs) -> Result<()> {
    use decoyrail::stats::{self, Breakdown, Window};

    let parse_date = |s: &str| -> Result<chrono::NaiveDate> {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
            .with_context(|| format!("bad date '{s}' (use YYYY-MM-DD)"))
    };
    let window = if args.line {
        // The one-liner is a fixed contract: today, three fields.
        Window::Today
    } else if args.since.is_some() || args.until.is_some() {
        let today = chrono::Local::now().date_naive();
        let since = match &args.since {
            Some(s) => parse_date(s)?,
            None => chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("epoch"),
        };
        let until = match &args.until {
            Some(s) => parse_date(s)?,
            None => today,
        };
        if since > until {
            return Err(anyhow!("--since {since} is after --until {until}"));
        }
        Window::Range { since, until }
    } else {
        match args.window.as_str() {
            "today" => Window::Today,
            "week" => Window::Week,
            "month" => Window::Month,
            "all" => Window::All,
            other => return Err(anyhow!("bad --window '{other}' (use today|week|month|all)")),
        }
    };
    let by = match args.by.as_str() {
        "session" => Breakdown::Session,
        "model" => Breakdown::Model,
        "host" => Breakdown::Host,
        "day" => Breakdown::Day,
        other => return Err(anyhow!("bad --by '{other}' (use session|model|host|day)")),
    };

    let report = stats::query(&window)?;
    if args.line {
        println!("{}", stats::render_line(&report));
    } else if args.json {
        println!("{}", stats::render_json(&report)?);
    } else {
        print!("{}", stats::render_human(&report, by));
    }
    Ok(())
}

fn license_cmd(cmd: LicenseCmd) -> Result<()> {
    use decoyrail::license;
    match cmd {
        LicenseCmd::Install { file } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let doc = license::parse_and_verify(&text, &license::trust_keys())
                .context("license rejected; nothing was installed")?;
            config::ensure_home()?;
            config::atomic_write(&config::license_path()?, text.as_bytes())?;
            // The install has already taken effect (a running proxy will hot
            // reload it), so an audit hiccup is a warning, not a failure the
            // exit code lies about.
            let note = format!(
                "license installed: licensee={} tier={} seats={} expires={}",
                doc.licensee,
                license::tier_of(&doc),
                doc.seats,
                doc.expires
            );
            let audited = audit::Auditor::open().and_then(|mut a| {
                a.append(audit::Entry::note("license", note), util::now_rfc3339())
            });
            if let Err(e) = audited {
                eprintln!("decoyrail: warning: license installed but audit append failed: {e:#}");
            }
            println!("License installed.");
            print_license(&doc);
        }
        LicenseCmd::Status => match license::load_installed() {
            Ok(Some(doc)) => print_license(&doc),
            Ok(None) => {
                println!(
                    "No license installed; running the free tier. Every security \
                     feature is included, free forever. Paid tiers add the cost \
                     pack and fleet tools: https://decoyrail.com/pricing"
                );
            }
            Err(e) => {
                println!("Installed license is invalid; running the free tier.");
                println!("  reason: {e:#}");
                println!("  (security features are unaffected; reinstall with `decoyrail license install`)");
            }
        },
    }
    Ok(())
}

fn print_license(doc: &decoyrail::license::LicenseDoc) {
    use decoyrail::license;
    let today = chrono::Utc::now().date_naive();
    let validity = license::evaluate(doc, today);
    println!("Licensee: {}", doc.licensee);
    println!(
        "Tier:     {} ({} seat(s))",
        license::effective_tier(doc, today),
        doc.seats
    );
    println!(
        "Term:     {} to {} (then {} grace day(s))",
        doc.issued, doc.expires, doc.grace_days
    );
    println!("Status:   {}", license::describe_validity(validity));
}

fn status_cmd() -> Result<()> {
    // One quiet tier line; licensing gates paid conveniences only, so this is
    // informational, never a nag.
    {
        use decoyrail::license;
        let today = chrono::Utc::now().date_naive();
        match license::load_installed() {
            Ok(Some(doc)) => {
                let mut line = format!(
                    "Tier: {} (licensed to {}, expires {})",
                    license::effective_tier(&doc, today),
                    doc.licensee,
                    doc.expires
                );
                if !matches!(license::evaluate(&doc, today), license::Validity::Valid) {
                    line.push_str(&format!(
                        "; {}",
                        license::describe_validity(license::evaluate(&doc, today))
                    ));
                }
                println!("{line}");
            }
            Ok(None) => println!("Tier: free"),
            Err(_) => {
                println!("Tier: free (installed license invalid; see `decoyrail license status`)")
            }
        }
    }
    let mut meter = meter::Meter::load()?;
    meter.roll_period(&util::current_period());
    println!(
        "Period: {}",
        if meter.period.is_empty() {
            "(none yet)".into()
        } else {
            meter.period.clone()
        }
    );
    println!(
        "Budget: {}",
        if meter.budget_usd > 0.0 {
            format!("${:.2}/mo", meter.budget_usd)
        } else {
            "unlimited".into()
        }
    );
    // max(0.0) avoids a "-0.0000" display when no metered spend has accrued.
    let metered = meter.metered_cost().max(0.0);
    let estimated = meter.estimated_cost().max(0.0);
    match (metered > 0.0, estimated > 0.0) {
        (true, true) => println!(
            "Spend: ${:.4} (${metered:.4} metered + ~${estimated:.4} estimated)",
            metered + estimated
        ),
        (true, false) => println!("Spend: ${metered:.4} (metered from provider token counts)"),
        (false, true) => println!("Spend: ~${estimated:.4} (estimated from bytes)"),
        (false, false) => println!("Spend: $0.0000"),
    }
    if meter.over_budget() {
        println!("  BUDGET EXHAUSTED: requests are being denied");
    }
    // Reference dollars are their own labeled line, never a share of Spend,
    // and the budget above never sees them.
    let absorbed = meter.plan_absorbed().max(0.0);
    if absorbed > 0.0 {
        println!(
            "Plan-absorbed: ~${absorbed:.4} API-equivalent (subscription traffic, not billed)"
        );
    }
    if let Ok(Some(price)) = meter::load_plan_price() {
        println!("Plan: {}", meter::plan_verdict(&price, absorbed));
    }
    if meter.per_host.is_empty() {
        println!("No traffic recorded this period.");
    } else {
        println!("Per destination:");
        // Column widths sized to the data so long names can't push fields out
        // of line. Host names and model names share one name column.
        let host_w = meter.per_host.keys().map(|h| h.len()).max().unwrap_or(0);
        let model_w = meter
            .per_host
            .values()
            .flat_map(|u| u.models.keys())
            .map(|m| m.len())
            .max()
            .unwrap_or(0);
        let host_w = host_w.max(model_w.saturating_add(2)).max(32);
        for (host, u) in &meter.per_host {
            let cost = match (u.metered_cost_usd() > 0.0, u.est_cost_usd > 0.0) {
                (true, true) => format!(
                    "  ${:.4} + ~${:.4} est",
                    u.metered_cost_usd(),
                    u.est_cost_usd
                ),
                (true, false) => format!("  ${:.4}", u.metered_cost_usd()),
                (false, true) => format!("  ~${:.4}", u.est_cost_usd),
                (false, false) => String::new(),
            };
            if u.models.is_empty() {
                // Non-LLM egress: volume is the interesting number.
                println!(
                    "  {host:<host_w$} {:>5} req  up {:>9}  down {:>9}{cost}",
                    u.requests,
                    fmt_bytes(u.bytes_up),
                    fmt_bytes(u.bytes_down)
                );
            } else {
                // LLM provider: tokens are the interesting number.
                println!("  {host:<host_w$} {:>5} req{cost}", u.requests);
                let rows: Vec<_> = u
                    .models
                    .iter()
                    .map(|(model, m)| {
                        let context = m.input_tokens + m.cache_read_tokens + m.cache_write_tokens;
                        let cached = if m.cache_read_tokens > 0 {
                            format!("({} cached)", fmt_tokens(m.cache_read_tokens))
                        } else {
                            String::new()
                        };
                        let cost = if model.ends_with("[subscription]") {
                            if m.ref_cost_usd > 0.0 {
                                format!("plan-covered (~${:.4} API-equivalent)", m.ref_cost_usd)
                            } else {
                                "plan-covered".to_string()
                            }
                        } else {
                            format!("${:.4}", m.cost_usd)
                        };
                        (
                            model,
                            fmt_tokens(context),
                            cached,
                            fmt_tokens(m.output_tokens),
                            cost,
                        )
                    })
                    .collect();
                let in_w = rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
                let cached_w = rows.iter().map(|r| r.2.len()).max().unwrap_or(0);
                let out_w = rows.iter().map(|r| r.3.len()).max().unwrap_or(0);
                for (model, tokens_in, cached, tokens_out, cost) in rows {
                    let cached = if cached_w > 0 {
                        format!(" {cached:<cached_w$}")
                    } else {
                        String::new()
                    };
                    println!(
                        "    {model:<w$} in {tokens_in:>in_w$}{cached}  out {tokens_out:>out_w$}  {cost}",
                        w = host_w - 2,
                    );
                }
            }
        }
    }
    Ok(())
}

/// The prompt-cache report: token counts and dollars from the meter (the
/// provider's own usage numbers), hygiene diagnosis from the cache doctor.
/// Free-tier, observe-only; the remediation half of plan 004 builds on it.
fn cache_cmd() -> Result<()> {
    let period = util::current_period();
    let mut m = meter::Meter::load()?;
    m.roll_period(&period);
    let mut stats = cache::CacheStats::load()?;
    if stats.period != period {
        stats.per_key.clear();
    }
    let pricing = pricing::Pricing::load()?;

    println!(
        "Prompt cache report (period {})",
        if m.period.is_empty() {
            "none yet"
        } else {
            &m.period
        }
    );

    let mut printed_any = false;
    let mut seen_keys: Vec<String> = Vec::new();
    for (host, u) in &m.per_host {
        let provider = pricing.provider_for_host(host);
        for (model_key, mu) in &u.models {
            let context = mu.input_tokens + mu.cache_read_tokens + mu.cache_write_tokens;
            if context == 0 {
                continue;
            }
            printed_any = true;
            let subscription = model_key.ends_with("[subscription]");
            let model = model_key.trim_end_matches(" [subscription]");
            println!("\n{host}  {model_key}");
            let hit_pct = mu.cache_read_tokens as f64 / context as f64 * 100.0;
            println!(
                "  context: {} fresh in / {} cache reads / {} cache writes -> {:.0}% read from cache",
                fmt_tokens(mu.input_tokens),
                fmt_tokens(mu.cache_read_tokens),
                fmt_tokens(mu.cache_write_tokens),
                hit_pct
            );
            if let Some(p) = provider {
                let rate = pricing.rate_for(p, Some(model));
                let saved =
                    mu.cache_read_tokens as f64 * (rate.input - rate.cache_read) / 1_000_000.0;
                if subscription {
                    println!(
                        "  plan-covered traffic; those cache reads spared ~${saved:.4} of \
                         API-equivalent input, which is plan headroom"
                    );
                } else if saved > 0.0 {
                    println!("  cache reads saved ~${saved:.4} vs full-price input");
                }
            }
            // The doctor doesn't split by billing mode, so a model with both
            // a usage row and a subscription row gets its hygiene block once,
            // on whichever row prints first (the waste framing follows that
            // row's billing).
            let doctor_key = format!("{host} {model}");
            if !seen_keys.contains(&doctor_key) {
                if let Some(s) = stats.per_key.get(&doctor_key) {
                    let waste = provider.map(|p| {
                        let rate = pricing.rate_for(p, Some(model));
                        (
                            cache::repairable_waste_usd(s.repairable_bytes, &rate),
                            subscription,
                        )
                    });
                    print_hygiene(s, waste);
                    seen_keys.push(doctor_key);
                }
            }
        }
    }
    // Doctor entries with no meter row yet (e.g. requests observed but no
    // usage parsed) still deserve their diagnosis.
    for (key, s) in &stats.per_key {
        if seen_keys.contains(key) {
            continue;
        }
        printed_any = true;
        println!("\n{key}");
        print_hygiene(s, None);
    }

    if !printed_any {
        println!(
            "No LLM cache activity recorded this period. Run an agent through \
             `decoyrail run` against an LLM provider host first."
        );
    }
    Ok(())
}

/// One model's hygiene lines from the doctor's counters. `waste` prices the
/// repairable re-billed prefix when the caller had a rate: the dollars and
/// whether the row is plan-covered, so subscription waste is framed as
/// headroom at reference rates instead of billed dollars (plan 019).
fn print_hygiene(s: &cache::KeyStats, waste: Option<(f64, bool)>) {
    println!(
        "  hygiene: {} requests ({} with cache markers); prefix preserved {}, new-conversation resets {}, diverged {}, past the 5-min TTL {}, below cacheable minimum {}",
        s.requests, s.marked, s.preserved, s.resets, s.diverged, s.ttl_gaps, s.below_min
    );
    if s.requests > 0 && s.marked == 0 {
        println!(
            "  note: no cache markers seen; this client never requests caching, \
             so every request re-bills its full context"
        );
    }
    if let Some(d) = &s.last_divergence {
        println!(
            "  last divergence: byte {} in {}, {}s after the previous request",
            d.offset, d.section, d.gap_secs
        );
        println!(
            "    something before that byte changes between requests (a timestamp? \
             an id?); every token after it re-bills at the full input rate"
        );
    }
    // Repair opportunity/action (plan 004 phase 2). `repairable` counts even
    // on the free tier, so the report can size the waste; `repaired` is
    // nonzero only when Pro + `[cache] repair` actually spliced markers in.
    if s.repairable > 0 || s.repaired > 0 {
        println!(
            "  repair: {} requests carried a repeating prefix with no cache marker; {} repaired",
            s.repairable, s.repaired
        );
        match waste {
            Some((usd, true)) if usd > 0.0 => println!(
                "    that re-billed prefix burned ~${usd:.4} of API-equivalent input: \
                 plan headroom spent on avoidable cache misses"
            ),
            Some((usd, false)) if usd > 0.0 => {
                println!("    that re-billed prefix wasted ~${usd:.4} against cache-read pricing")
            }
            _ => {}
        }
        if s.repaired == 0 {
            println!(
                "    Decoyrail can inject those markers for you (Pro): set `[cache] repair = true` \
                 in the policy to cache the repeating prefix instead of re-billing it"
            );
        }
    }
}

/// Declare, show, or clear the local plan price (plan 019). Bare `decoyrail
/// plan` reads this period's plan-absorbed total against the declared price;
/// the price is one local setting the user owns, never guessed.
fn plan_cmd(args: PlanArgs) -> Result<()> {
    if args.clear {
        meter::clear_plan_price()?;
        println!("Plan price cleared.");
        return Ok(());
    }
    let existing = meter::load_plan_price()?;
    if args.price.is_none() && args.label.is_none() {
        let mut m = meter::Meter::load()?;
        m.roll_period(&util::current_period());
        let absorbed = m.plan_absorbed().max(0.0);
        match existing {
            Some(p) => println!("{}", meter::plan_verdict(&p, absorbed)),
            None => {
                if absorbed > 0.0 {
                    println!(
                        "Plan-absorbed this period: ~${absorbed:.4} API-equivalent \
                         (subscription traffic, not billed)."
                    );
                } else {
                    println!("No plan-covered traffic this period.");
                }
                println!(
                    "No plan price declared. Set one with \
                     `decoyrail plan --price 200 --label \"Claude Max\"` to see \
                     what the plan absorbs against what it costs."
                );
            }
        }
        return Ok(());
    }
    let usd = match (args.price, &existing) {
        (Some(usd), _) => usd,
        (None, Some(p)) => p.usd,
        (None, None) => return Err(anyhow!("no plan price declared yet; pass --price")),
    };
    // `<= 0.0` alone would let NaN through; require a real positive number.
    if usd.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return Err(anyhow!(
            "plan price must be a positive dollar amount; use --clear to remove it"
        ));
    }
    let label = args.label.or(existing.map(|p| p.label)).unwrap_or_default();
    let price = meter::PlanPrice { usd, label };
    meter::save_plan_price(&price)?;
    if price.label.is_empty() {
        println!("Plan price set: ${usd:.2}/mo.");
    } else {
        println!("Plan price set: {} at ${usd:.2}/mo.", price.label);
    }
    Ok(())
}

fn budget_cmd(usd: f64) -> Result<()> {
    // Write the budget file only — never the meter's usage — so setting a
    // budget while the proxy is running can't clobber recorded usage (and the
    // proxy's usage writes can't clobber the budget).
    meter::save_budget(usd)?;
    if usd > 0.0 {
        println!("Monthly budget set to ${usd:.2}.");
    } else {
        println!("Budget cleared (unlimited).");
    }
    Ok(())
}

/// rustls needs a process-wide crypto provider installed before use.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
