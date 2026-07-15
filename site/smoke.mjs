// Post-deploy smoke test for decoyrail.com. Asserts the deployed site against
// the route manifest the local build just produced (site/dist/routes.json),
// so "deploy succeeded" means "the site serves this release", not "the CDN
// returned 200 for everything".
//
//   node site/build.mjs && node site/smoke.mjs [base-url]
//
// Base URL defaults to https://www.decoyrail.com. Exits non-zero on the first
// failure summary; checks:
//   - every public route returns 200 and contains its page-identity marker
//     (a catch-all serving the landing page everywhere fails here)
//   - the landing page shows this build's version
//   - an unknown route returns a real 404 with the custom page
//   - security headers are present
//   - the release tarball on the tap repo's GitHub release (the URL the site
//     and the Homebrew formula share) downloads and matches the manifest sha256
//   - robots.txt still carries the pre-launch disallow (remove at launch)
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const SITE = dirname(fileURLToPath(import.meta.url));
const BASE = (process.argv[2] ?? 'https://www.decoyrail.com').replace(/\/$/, '');

let manifest;
try {
  manifest = JSON.parse(readFileSync(join(SITE, 'dist/routes.json'), 'utf8'));
} catch {
  console.error('smoke: site/dist/routes.json missing; run `node site/build.mjs` first');
  process.exit(2);
}

const failures = [];
const ok = (cond, what) => {
  console.log(`${cond ? '  ok ' : 'FAIL '} ${what}`);
  if (!cond) failures.push(what);
};

const get = (path) => fetch(BASE + path, { redirect: 'follow' });

for (const { path, marker } of manifest.routes) {
  const res = await get(path);
  const body = await res.text();
  ok(res.status === 200, `${path} returns 200 (got ${res.status})`);
  ok(body.includes(marker), `${path} is its intended page (${marker})`);
  if (path === '/') {
    ok(body.includes(`v${manifest.version}`), `/ shows v${manifest.version}`);
    ok(res.headers.get('x-content-type-options') === 'nosniff', '/ has nosniff');
    ok((res.headers.get('content-security-policy') ?? '').includes("default-src 'self'"), '/ has CSP');
  }
}

{
  const path = '/definitely-not-a-page-' + manifest.sha256.slice(0, 12);
  const res = await get(path);
  const body = await res.text();
  ok(res.status === 404, `unknown route returns 404 (got ${res.status})`);
  ok(body.includes('<title>Not found · Decoyrail</title>'), 'unknown route serves the custom 404 page');
}

{
  // The tarball lives on the public tap repo's GitHub release (absolute URL
  // in the manifest); this asserts the artifact the site and the Homebrew
  // formula both point at actually serves, anonymously, with the pinned hash.
  const res = await fetch(manifest.tarball, { redirect: 'follow' });
  ok(res.status === 200, `release tarball downloads (got ${res.status})`);
  if (res.status === 200) {
    const buf = Buffer.from(await res.arrayBuffer());
    const sha = createHash('sha256').update(buf).digest('hex');
    ok(sha === manifest.sha256, `release tarball sha256 matches the build (${sha.slice(0, 12)}…)`);
  }
}

{
  const res = await get('/robots.txt');
  const body = await res.text();
  ok(res.status === 200 && /Disallow: \//.test(body),
    'robots.txt still disallows indexing (pre-launch; drop this check at public launch)');
}

if (failures.length) {
  console.error(`\nsmoke: ${failures.length} check(s) failed against ${BASE}`);
  process.exit(1);
}
console.log(`\nsmoke: all checks passed against ${BASE}`);
