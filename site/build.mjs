// Static site builder for decoyrail.com: landing page + docs rendered from
// the repo's markdown. Output goes to site/dist/, deployed to Cloudflare Pages.
import { marked } from 'marked';
import { readFileSync, writeFileSync, mkdirSync, rmSync, cpSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const SITE = dirname(fileURLToPath(import.meta.url));
const REPO = join(SITE, '..');
const DIST = join(SITE, 'dist');

const VERSION = /^version\s*=\s*"([^"]+)"/m.exec(
  readFileSync(join(REPO, 'Cargo.toml'), 'utf8'),
)[1];
// Release artifacts are hosted on the public source repo. The site links
// there instead of serving its own copy: one binary per version, one sha256,
// and the formula, the site, and the smoke test all agree.
const SRC_REPO = 'decoyrail-team/decoyrail';
const TARBALL = `decoyrail-v${VERSION}-aarch64-apple-darwin.tar.gz`;
const RELEASE_URL = `https://github.com/${SRC_REPO}/releases/tag/v${VERSION}`;
const DL_URL = `https://github.com/${SRC_REPO}/releases/download/v${VERSION}/${TARBALL}`;

// ---------------------------------------------------------------- markdown

const escapeHtml = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const slug = (text) =>
  text.toLowerCase().replace(/<[^>]*>/g, '').replace(/&[a-z#0-9]+;/g, ' ')
    .replace(/[`*_]/g, '').replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-');

const renderer = new marked.Renderer();
renderer.code = (code, lang) =>
  lang === 'mermaid'
    ? `<pre class="mermaid">${escapeHtml(code)}</pre>\n`
    : `<pre class="code"><code>${escapeHtml(code)}</code></pre>\n`;
renderer.heading = (text, level) =>
  `<h${level} id="${slug(text)}">${text}</h${level}>\n`;
renderer.table = (header, body) =>
  `<div class="table-wrap"><table><thead>${header}</thead><tbody>${body}</tbody></table></div>\n`;
marked.setOptions({ renderer, gfm: true });

// Rewrite same-tree markdown links (foo.md, foo.md#anchor) to .html.
const rewriteLinks = (md) =>
  md.replace(/\]\((?!https?:|#)([\w./-]+)\.md(#[^)]*)?\)/g, ']($1$2)');

// On the site, ROADMAP.md is a docs page next to the other docs.
const renderMd = (md) =>
  marked.parse(rewriteLinks(md).replace(/\]\((?:\.\.\/)?ROADMAP(#[^)]*)?\)/g, '](roadmap$1)'));

// ------------------------------------------------------------------ pages

const DOCS = [
  { src: 'docs/README.md',            out: 'index.html',             title: 'Overview' },
  { src: 'docs/getting-started.md',   out: 'getting-started.html',   title: 'Getting started' },
  { src: 'docs/how-it-works.md',      out: 'how-it-works.html',      title: 'How it works' },
  { src: 'docs/policy.md',            out: 'policy.html',            title: 'Policy reference' },
  { src: 'docs/vault-and-bindings.md',out: 'vault-and-bindings.html',title: 'Vault & bindings' },
  { src: 'docs/dlp.md',               out: 'dlp.html',               title: 'Sensitive-data filtering' },
  { src: 'docs/audit-and-metering.md',out: 'audit-and-metering.html',title: 'Audit & metering' },
  { src: 'docs/stats.md',             out: 'stats.html',             title: 'Analytics' },
  { src: 'docs/license.md',           out: 'license.html',           title: 'Licensing' },
  { src: 'docs/threat-model.md',      out: 'threat-model.html',      title: 'Threat model' },
  { src: 'ROADMAP.md',                out: 'roadmap.html',           title: 'Roadmap' },
];

// The public site must not reference the internal strategy docs.
function scrubInternal(src, md) {
  if (src === 'docs/README.md') {
    md = md.replace(/What's coming next[\s\S]*$/, "What's coming next is in the [roadmap](roadmap).\n");
  }
  if (src === 'ROADMAP.md') {
    // The repo intro links to README.md files that aren't site pages.
    md = md.replace(/For what works[\s\S]*?\(docs\/README\.md\)\./,
      'For what works *today*, see the [docs](./).');
  }
  return md;
}

// Must be an external file: the site's CSP has no 'unsafe-inline' for scripts.
const MERMAID_INIT_SRC = `import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
mermaid.initialize({ startOnLoad: true, theme: "neutral", securityLevel: "strict",
  themeVariables: { fontFamily: "ui-monospace, SF Mono, Menlo, monospace", fontSize: "14px" } });
`;
const MERMAID_INIT = '<script type="module" src="../mermaid-init.mjs"></script>';

const head = (title, root) => `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="Decoyrail is an endpoint firewall for AI agents. Agents hold decoy credentials; a local proxy swaps in real secrets only for approved destinations and alarms on everything else.">
<link rel="stylesheet" href="${root}style.css">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%AA%A4%3C/text%3E%3C/svg%3E">`;

const topnav = (root) => `<header class="topnav">
  <a class="brand" href="${root}">decoy<span>rail</span></a>
  <nav>
    <a href="${root}docs/">Docs</a>
    <a href="${root}pricing">Pricing</a>
    <a href="${root}docs/roadmap">Roadmap</a>
    <a href="https://github.com/decoyrail-team/decoyrail">GitHub</a>
    <a class="btn small" href="${root}#download">Install</a>
  </nav>
</header>`;

const footer = `<footer class="footer">
  <p>Decoyrail is an endpoint firewall for AI agents. The core is licensed
  <a href="https://fsl.software">FSL-1.1-ALv2</a> (source-available; each release
  becomes Apache-2.0 after two years). The source lives on
  <a href="https://github.com/decoyrail-team/decoyrail">GitHub</a>.</p>
  <p>&copy; 2026 Decoyrail authors</p>
</footer>`;

function docsPage({ out, title }, contentHtml) {
  const nav = DOCS.map((d) =>
    `<a href="${d.out === 'index.html' ? './' : d.out.replace(/\.html$/, '')}"${d.out === out ? ' class="active"' : ''}>${d.title}</a>`,
  ).join('\n      ');
  return `<!doctype html>
<html lang="en"><head>${head(`${title} · Decoyrail docs`, '../')}</head>
<body class="docs">
${topnav('../')}
<div class="docs-layout">
  <aside class="sidebar"><nav>
      <p class="sidebar-label">Documentation</p>
      ${nav}
  </nav></aside>
  <main class="doc-content">
${contentHtml}
  </main>
</div>
${footer}
${MERMAID_INIT}
</body></html>`;
}

// ------------------------------------------------------------------ build

rmSync(DIST, { recursive: true, force: true });
mkdirSync(join(DIST, 'docs'), { recursive: true });

// Every generated page must be free of internal-strategy references, and
// house style bans em dashes in all site copy.
const checkCopy = (name, html) => {
  for (const banned of ['SPEC.md', 'TODO.md', 'SPEC.html', 'TODO.html']) {
    if (html.includes(banned)) throw new Error(`${name}: leaked reference to ${banned}`);
  }
  if (/[—–]/.test(html)) throw new Error(`${name}: em/en dash in copy`);
};

for (const page of DOCS) {
  const md = scrubInternal(page.src, readFileSync(join(REPO, page.src), 'utf8'));
  const html = docsPage(page, renderMd(md));
  checkCopy(page.src, html);
  writeFileSync(join(DIST, 'docs', page.out), html);
}

// Demo GIFs the docs embed (docs/demos/*.gif; the .tape sources stay repo-only).
mkdirSync(join(DIST, 'docs', 'demos'), { recursive: true });
for (const f of readdirSync(join(REPO, 'docs/demos'))) {
  if (f.endsWith('.gif')) cpSync(join(REPO, 'docs/demos', f), join(DIST, 'docs', 'demos', f));
}

// The release tarball's sha256, so the page (and the smoke test) can pin the
// GitHub-hosted artifact. At release time scripts/release.sh has just written
// it to target/release-dist; otherwise read it off the published release, so
// the page never shows a hash the download can't match.
const shaFile = join(REPO, `target/release-dist/${TARBALL}.sha256`);
let SHA;
if (existsSync(shaFile)) {
  SHA = readFileSync(shaFile, 'utf8').split(' ')[0];
} else {
  const res = await fetch(`${DL_URL}.sha256`, { redirect: 'follow' });
  if (!res.ok) {
    throw new Error(`no ${shaFile} and ${DL_URL}.sha256 returned ${res.status}; ` +
      'release v' + VERSION + ' must be published to the source repo first');
  }
  SHA = (await res.text()).split(' ')[0];
}
if (!/^[0-9a-f]{64}$/.test(SHA)) throw new Error(`bad sha256 for ${TARBALL}: ${SHA}`);

// ------------------------------------------------------------- landing page

const landing = `<!doctype html>
<html lang="en"><head>${head('Decoyrail: endpoint firewall for AI agents', '')}</head>
<body>
${topnav('')}
<main>
<section class="hero">
  <p class="kicker">Endpoint firewall for AI agents</p>
  <h1>Your coding agent works with decoy credentials.<br>Real secrets never enter its environment.</h1>
  <p class="lede">Decoyrail is a single binary that runs Claude Code, Codex CLI,
  or any coding agent behind a local proxy. The agent holds
  <strong>decoys</strong>. The proxy swaps in the real secret only for that
  secret's approved destination, blocks everything else, and raises an alarm
  the moment a decoy heads anywhere it should not. If the agent is tricked
  into leaking a key, the key it leaks works nowhere.</p>
  <p class="cta">
    <a class="btn primary" href="#download">Install for macOS</a>
    <a class="btn" href="docs/getting-started">Get started in 5 minutes</a>
  </p>
</section>

<section class="demo">
  <h2>Watch it catch an exfiltration</h2>
  <p>A prompt injection tells the agent to send its AWS key somewhere it
  should not go. The key the agent holds is a decoy, so the request is blocked
  and the attempt lands in the log:</p>
  <figure><img src="docs/demos/tripwire.gif" width="1200" height="640"
    alt="A decoy AWS key sent to an unapproved host is blocked, and decoyrail log records the exfiltration attempt"></figure>
</section>

<section class="terminal-demo">
  <h2>The whole setup is one command</h2>
<pre class="code"><code><span class="dim"># Run your agent behind Decoyrail. With a Claude subscription this is
# everything: default-deny egress, an audit log, and every
# credential-looking env var in your terminal replaced with a decoy.</span>
$ decoyrail run -- claude

<span class="dim"># In a second terminal, watch every decision live.</span>
$ decoyrail log -t
<span class="ok">allow</span>     api.anthropic.com POST /v1/messages
<span class="alarm">tripwire</span>  decoy 'aws' seen toward evil.example.com: blocked

<span class="dim"># Only if you pay per token with an API key: vault it. The agent then
# sees a decoy; api.anthropic.com receives the real key.</span>
$ decoyrail vault add --name anthropic --env ANTHROPIC_API_KEY --location bearer</code></pre>
  <p class="note">No vault setup is needed for the common case.
  <code>decoyrail run</code> spots credential-looking variables in your
  terminal (<code>AWS_SECRET_ACCESS_KEY</code>, <code>GITHUB_TOKEN</code>, and
  so on) and hands the agent decoys automatically:</p>
  <figure><img src="docs/demos/auto-decoy.gif" width="1200" height="640"
    alt="decoyrail run replaces sensitive env vars with decoys before launching the agent"></figure>
</section>

<section class="cols3">
  <div><h3>Decoys, not redaction</h3><p>Real secrets stay encrypted on disk
  and exist only inside the proxy. The agent, its logs, its prompts, and its
  crash dumps can only ever contain fakes that look real
  (<code>sk-ant-…</code>, <code>ghp_…</code>, <code>AKIA…</code>), so stock
  SDKs accept them without any special-casing.</p></div>
  <div><h3>The swap is narrow</h3><p>The real secret goes out only when the
  host, path, method, and location all match what you bound it to, and only
  over verified TLS. The proxy never follows a redirect, so a secret cannot
  be bounced somewhere the policy never looked at.</p></div>
  <div><h3>Stolen decoys tell on the thief</h3><p>Every decoy is a honeytoken.
  If one shows up outside its binding, even base64, hex, or percent-encoded,
  the request is blocked and the alarm is logged. You find out the moment
  anyone tries to use it.</p></div>
</section>

<section class="features">
  <h2>What's in the box</h2>
  <div class="grid">
    <div><h4>Default-deny egress policy</h4><p>Nothing leaves unless a rule
    allows it, and the rule that allows a destination also says which secrets
    it releases. A starter pack covers what coding agents need.</p></div>
    <div><h4>TLS interception done carefully</h4><p>A CA minted on your device,
    per-host certificates, and a fresh, fully verified connection upstream.
    Enterprise internal CAs are additive, never a bypass.</p></div>
    <div><h4>Streaming stays fast</h4><p>Token streams pass through untouched.
    Bounded responses are scanned for echoed real secrets.</p></div>
    <div><h4>An audit log you can trust</h4><p>Append-only and hash-chained.
    <code>decoyrail log --verify</code> catches edits, deletions, and
    truncation.</p></div>
    <div><h4>Spend metering &amp; budget</h4><p>Exact per-model token counts,
    a monthly budget, and a kill switch that denies requests once the budget
    is spent.</p></div>
    <div><h4>Offline by design</h4><p>No account, no server, no telemetry.
    Nothing about your traffic ever reaches us.</p></div>
  </div>
</section>

<section class="honesty">
  <h2>An honest threat model</h2>
  <p>Today Decoyrail runs as your user and guards the network path your agent
  is configured through. That covers accidental secret leaks, prompt-injected
  exfiltration, off-policy egress, and audit-history tampering. It is
  <strong>not</strong> yet a boundary against hostile code running as you: a
  same-user process can still read <code>~/.decoyrail</code> off disk or edit
  the policy (the privileged system mode on the roadmap closes that). An agent
  that sidesteps the proxy gains nothing: its requests fail, and the decoys it
  carries work nowhere. For a security product, the limits are part of the
  product: <a href="docs/threat-model">read the full threat model</a>.</p>
</section>

<section id="download" class="download">
  <h2>Install</h2>
  <p class="dl-meta">v${VERSION} · macOS · Apple Silicon</p>
<pre class="code"><code><span class="dim"># install with Homebrew</span>
brew install decoyrail-team/tap/decoyrail

<span class="dim"># first run (with a Claude subscription, this is everything)</span>
decoyrail ca install
decoyrail run -- claude

<span class="dim"># only if you use an API key instead of a subscription:</span>
decoyrail vault add --name anthropic --env ANTHROPIC_API_KEY --location bearer</code></pre>
  <p class="note">No Homebrew? Download
  <a href="${DL_URL}">${TARBALL}</a> from the
  <a href="${RELEASE_URL}">GitHub release</a>
  (sha256 <code>${SHA}</code>) and put <code>decoyrail</code> on your PATH:</p>
<pre class="code"><code>curl -LO ${DL_URL}
shasum -a 256 -c &lt;(echo "${SHA}  ${TARBALL}")
tar xzf ${TARBALL}
mkdir -p ~/.local/bin &amp;&amp; mv decoyrail-v${VERSION}-aarch64-apple-darwin/decoyrail ~/.local/bin/</code></pre>
  <p class="note">This is a pre-release build, not yet codesigned or notarized.
  Homebrew and <code>curl</code> installs don't trip Gatekeeper; a browser
  download will be quarantined (clear it with
  <code>xattr -d com.apple.quarantine decoyrail</code>).
  Free for individual use; the core is source-available under FSL-1.1-ALv2 so you
  can audit the binary that intercepts your TLS.</p>
</section>
</main>
${footer}
</body></html>`;

checkCopy('landing', landing);
writeFileSync(join(DIST, 'index.html'), landing);

// ------------------------------------------------------------- pricing page
// Tier contents live in ONE structure (the matrix); the cards reference rows
// by label so the two can never drift apart. Availability values: true =
// works today; 'v0.x' = on the public roadmap, tagged in the cell (the
// honesty rule: no vaporware checkmarks); '' = not in that tier.

const CONTACT_EMAIL = 'license@decoyrail.com';
const contact = (plan) =>
  `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(`Decoyrail ${plan}`)}`;

// Columns: [Free, Pro, Team, Enterprise]
const MATRIX = [
  { group: 'Security', intro: 'Free in every tier, forever. A security product with a crippled free tier is not a security product you can trust.', rows: [
    ['Decoy credentials with the real-secret swap', [true, true, true, true]],
    ['Exfiltration tripwires, including encoded forms', [true, true, true, true]],
    ['Default-deny egress policy', [true, true, true, true]],
    ['Sensitive-data detectors (cards, SSNs, bank ids)', [true, true, true, true]],
    ['Tamper-evident audit log with live tail', [true, true, true, true]],
    ['TLS interception with a per-device CA', [true, true, true, true]],
    ['Spend tripwire (runaway loops caught in minutes)', ['v0.3', 'v0.3', 'v0.3', 'v0.3']],
  ]},
  { group: 'Cost', intro: 'The free tier measures the waste with exact numbers; the paid tiers fix it automatically.', rows: [
    ['Exact per-model token metering', [true, true, true, true]],
    ['Monthly budget and kill switch', [true, true, true, true]],
    ['The waste report, in dollars, with causes', ['v0.3', 'v0.3', 'v0.3', 'v0.3']],
    ['Budget soft-landing (downgrade, not dead stop)', ['', 'v0.3', 'v0.3', 'v0.3']],
    ['Prompt-cache repair and keep-alive', ['', 'v0.3', 'v0.3', 'v0.3']],
    ['Model routing by policy', ['', 'v0.3', 'v0.3', 'v0.3']],
  ]},
  { group: 'Fleet', intro: 'One pane of glass once agents run on more machines than yours.', rows: [
    ['Admin console with policy dry-run', ['', '', 'v0.4', 'v0.4']],
    ['Signed policy push with rollback', ['', '', 'v0.4', 'v0.4']],
    ['Machine enrollment and seat attribution', ['', '', 'v0.4', 'v0.4']],
    ['Fleet spend roll-up and chargeback export', ['', '', 'v0.4', 'v0.4']],
    ['Org budgets and model rules', ['', '', 'v0.4', 'v0.4']],
    ['Maintained agent policy packs', ['', '', 'v0.5', 'v0.5']],
  ]},
  { group: 'Deployment & compliance', intro: 'What a large rollout and its auditors need.', rows: [
    ['Offline license file, no phone-home ever', ['', true, true, true]],
    ['MDM deployment (.pkg, Jamf, Kandji)', ['', '', '', 'v1']],
    ['SSO / SCIM seat management', ['', '', '', 'v1']],
    ['SIEM content packs (dashboards, alert rules)', ['', '', '', 'v0.4']],
    ['Compliance packs (SOC 2, ISO 27001 evidence)', ['', '', '', 'v0.5']],
    ['Air-gapped licensing and delivery', ['', '', '', true]],
    ['Cross-provider rewrite onto committed cloud spend', ['', '', '', 'v2']],
  ]},
  { group: 'Support', rows: [
    ['Community (GitHub issues)', [true, true, true, true]],
    ['Email support', ['', true, true, true]],
    ['Priority support with an SLA', ['', '', '', true]],
  ]},
];

const TIER_INDEX = { Free: 0, Pro: 1, Team: 2, Enterprise: 3 };
const findRow = (label) => {
  for (const g of MATRIX) for (const r of g.rows) if (r[0] === label) return r;
  throw new Error(`pricing card references unknown matrix row: ${label}`);
};
const tag = (v) => (typeof v === 'string' && v ? ` <span class="tag">${v}</span>` : '');

const PLANS = [
  {
    name: 'Free', price: '$0', per: 'one seat, forever', annual: '',
    buyer: 'For every individual, on all of their own machines. Commercial use included.',
    features: [
      'Decoy credentials with the real-secret swap',
      'Exfiltration tripwires, including encoded forms',
      'Default-deny egress policy',
      'Sensitive-data detectors (cards, SSNs, bank ids)',
      'Tamper-evident audit log with live tail',
      'Exact per-model token metering',
    ],
    cta: { label: 'Install for macOS', href: '/#download', primary: false },
  },
  {
    name: 'Pro', price: '$10', per: 'per seat per month', annual: 'or $96 per seat per year',
    buyer: 'For anyone paying real money for API tokens. Everything in Free, plus the fixes:',
    features: [
      'Budget soft-landing (downgrade, not dead stop)',
      'Prompt-cache repair and keep-alive',
      'Model routing by policy',
      'Email support',
    ],
    cta: { label: 'Get launch pricing', href: contact('Pro'), primary: true },
    featured: true,
  },
  {
    name: 'Team', price: '$15', per: 'per seat per month', annual: 'or $144 per seat per year',
    buyer: 'For the lead running agents across a group. Everything in Pro, plus:',
    features: [
      'Admin console with policy dry-run',
      'Signed policy push with rollback',
      'Machine enrollment and seat attribution',
      'Fleet spend roll-up and chargeback export',
      'Org budgets and model rules',
    ],
    cta: { label: 'Talk to us', href: contact('Team'), primary: false },
  },
  {
    name: 'Enterprise', price: 'from $30', per: 'per seat per month, annual', annual: 'invoice or PO',
    buyer: 'For fleets, auditors, and air gaps. Everything in Team, plus:',
    features: [
      'MDM deployment (.pkg, Jamf, Kandji)',
      'SSO / SCIM seat management',
      'SIEM content packs (dashboards, alert rules)',
      'Air-gapped licensing and delivery',
      'Priority support with an SLA',
    ],
    cta: { label: 'Talk to us', href: contact('Enterprise'), primary: false },
  },
];

const planCard = (p) => {
  const items = p.features.map((label) => {
    const avail = findRow(label)[1][TIER_INDEX[p.name]];
    // The anti-drift guard: a card may only advertise what the matrix says
    // its tier actually has, with the same roadmap tag.
    if (avail === '') {
      throw new Error(`pricing card '${p.name}' lists '${label}' but the matrix says the tier lacks it`);
    }
    return `<li>${label}${tag(avail)}</li>`;
  }).join('\n      ');
  return `<div class="plan${p.featured ? ' featured' : ''}">
    <h3>${p.name}</h3>
    <p class="price">${p.price} <span>${p.per}</span></p>
    <p class="annual">${p.annual || '&nbsp;'}</p>
    <p class="buyer">${p.buyer}</p>
    <ul>
      ${items}
    </ul>
    <p class="cta-row"><a class="btn${p.cta.primary ? ' primary' : ''}" href="${p.cta.href}">${p.cta.label}</a></p>
  </div>`;
};

const matrixCell = (v) =>
  v === '' ? '<td class="off"></td>'
    : v === true ? '<td class="on">✓</td>'
      : `<td class="on">✓ <span class="tag">${v}</span></td>`;

const matrixRows = MATRIX.map((g) => {
  const intro = g.intro ? ` <span class="group-intro">${g.intro}</span>` : '';
  const head = `<tr class="group"><td colspan="5"><strong>${g.group}</strong>${intro}</td></tr>`;
  const rows = g.rows.map((r) =>
    `<tr><td>${r[0]}</td>${r[1].map(matrixCell).join('')}</tr>`,
  ).join('\n');
  return `${head}\n${rows}`;
}).join('\n');

const FAQ = [
  ['Why is every security feature free?',
   `Because a TLS-intercepting proxy lives or dies on trust, and charging to
    turn protection on is a bad way to earn it. The rule that decides every tier
    boundary: security is never paywalled; the business is efficiency (the
    cost pack) and fleet management. The free tier's exact waste numbers are
    also, frankly, the ad for Pro.`],
  ['What happens when a license expires?',
   `You get a grace window (14 days by default) where everything keeps
    working and <code>decoyrail license status</code> warns. After it, paid
    conveniences switch off in their safe direction: soft-landing reverts to
    the hard kill switch, routing stops rewriting, and you keep every
    security feature, forever. An expired license can never block traffic or
    weaken enforcement; that is a design invariant, not a promise.`],
  ['Do endpoints phone home?',
   `Never. The license is a signed file verified offline against keys inside
    the binary; there is no license server, no activation, and no telemetry.
    Nothing about your traffic ever flows to us. This is also why Decoyrail
    works fully air-gapped.`],
  ['What counts as a seat?',
   `A human. One person's seat covers all of that person's machines. Seat
    counts are enforced by the license terms and console warnings, not by
    bricking endpoints: a fleet that drifts over its count keeps running
    while you true it up.`],
  ['How does buying work in an air-gapped environment?',
   `Invoice or PO, and we deliver a license file you carry in alongside your
    policy bundle. Verification is offline by construction, so nothing about
    an air gap is a special case.`],
  ['Can I audit the binary that intercepts my TLS?',
   `Yes. The endpoint core is source-available under
    <a href="https://fsl.software">FSL-1.1-ALv2</a> (each release becomes
    Apache-2.0 after two years), so your security team can read and build
    the exact code that holds your keys.`],
  ['When can I buy Pro?',
   `The cost pack ships in v0.3 (see the <a href="docs/roadmap">roadmap</a>),
    and Pro goes on sale when the features on this page are real, not
    before. Email us and we will let you know the moment it is live.`],
  ['Can I cancel?',
   `Any time. The term you paid for runs out, then the product downgrades
    itself to the free tier, gracefully. There is nothing to uninstall and
    nothing held back: your vault, policy, and audit log are yours and stay
    fully functional.`],
];
const faqHtml = FAQ.map(([q, a]) =>
  `<details><summary>${q}</summary><p>${a}</p></details>`,
).join('\n');

// Root is './' (not ''): the topnav Install button must resolve to the
// landing page's anchor, and './#download' does from /pricing while a bare
// '#download' would dead-end on this page.
const pricingPage = `<!doctype html>
<html lang="en"><head>${head('Pricing · Decoyrail', './')}</head>
<body>
${topnav('./')}
<main>
<section class="hero pricing-hero">
  <p class="kicker">Pricing</p>
  <h1>Every security feature is free. Forever.</h1>
  <p class="lede">Decoyrail makes money when it saves you money and runs your
  fleet, not by holding protection hostage. Decoys, tripwires, egress policy,
  data detectors, the audit log, and exact spend metering are free for
  individuals, with no caps and no fuzzy numbers. The paid tiers cut your
  token bill and manage many machines.</p>
</section>

<section class="pricing-grid-wrap">
  <div class="pricing-grid">
    ${PLANS.map(planCard).join('\n    ')}
  </div>
</section>

<section class="compare">
  <h2>Compare the tiers</h2>
  <p class="note">A version tag (<span class="tag">v0.3</span>) marks a
  feature on the public <a href="docs/roadmap">roadmap</a> that has not
  shipped yet. Everything untagged works today. We would rather show you the
  tags than sell you a checkmark.</p>
  <div class="table-wrap"><table class="tier-table">
    <thead><tr><th></th><th>Free</th><th>Pro</th><th>Team</th><th>Enterprise</th></tr></thead>
    <tbody>
${matrixRows}
    </tbody>
  </table></div>
</section>

<section class="faq">
  <h2>Questions</h2>
${faqHtml}
  <p class="note">Anything else: <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p>
</section>
</main>
${footer}
</body></html>`;

checkCopy('pricing', pricingPage);
writeFileSync(join(DIST, 'pricing.html'), pricingPage);

// -------------------------------------------------------------------- 404
// Without a top-level 404.html, Cloudflare Pages treats the deployment as a
// single-page app and serves index.html with HTTP 200 for every unknown
// route. That catch-all hid missing pages from status checks and crawlers;
// this file is what switches real 404 behavior on. Do not remove it.
const notFound = `<!doctype html>
<html lang="en"><head>${head('Not found · Decoyrail', '/')}</head>
<body>
${topnav('/')}
<main>
<section class="hero">
  <p class="kicker">404</p>
  <h1>There is no page here.</h1>
  <p class="lede">The address may be stale or mistyped. Try the
  <a href="/">home page</a>, the <a href="/docs/">docs</a>, or
  <a href="/pricing">pricing</a>.</p>
</section>
</main>
${footer}
</body></html>`;
checkCopy('404', notFound);
writeFileSync(join(DIST, '404.html'), notFound);

cpSync(join(SITE, 'assets/style.css'), join(DIST, 'style.css'));
writeFileSync(join(DIST, 'mermaid-init.mjs'), MERMAID_INIT_SRC);

// ---------------------------------------------------------- route manifest
// Every public route with the marker that identifies its intended page (the
// unique <title>), plus the release identity. site/smoke.mjs asserts all of
// it against the deployed site, so a stale deployment or a catch-all serving
// the landing page everywhere fails loudly instead of returning HTTP 200.
const MANIFEST = {
  version: VERSION,
  tarball: DL_URL,
  sha256: SHA,
  routes: [
    { path: '/', marker: '<title>Decoyrail: endpoint firewall for AI agents</title>' },
    { path: '/pricing', marker: '<title>Pricing · Decoyrail</title>' },
    ...DOCS.map((d) => ({
      path: `/docs/${d.out === 'index.html' ? '' : d.out.replace(/\.html$/, '')}`,
      marker: `<title>${d.title} · Decoyrail docs</title>`,
    })),
  ],
};
writeFileSync(join(DIST, 'routes.json'), JSON.stringify(MANIFEST, null, 2) + '\n');

// Cloudflare Pages extras: security headers.
writeFileSync(join(DIST, '_headers'), `/*
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'
`);
// Old bookmarked download links: send them to the release listing.
writeFileSync(join(DIST, '_redirects'),
  `/download/* https://github.com/${SRC_REPO}/releases/latest 302\n`);
// Public launch: invite crawlers, and give them a sitemap built from the
// same route manifest the smoke test asserts.
const ORIGIN = 'https://www.decoyrail.com';
writeFileSync(join(DIST, 'robots.txt'),
  `User-agent: *\nAllow: /\n\nSitemap: ${ORIGIN}/sitemap.xml\n`);
writeFileSync(join(DIST, 'sitemap.xml'),
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  MANIFEST.routes.map((r) => `  <url><loc>${ORIGIN}${r.path}</loc></url>`).join('\n') +
  '\n</urlset>\n');

console.log(`built dist/: decoyrail v${VERSION}, ${TARBALL} sha256 ${SHA}`);
