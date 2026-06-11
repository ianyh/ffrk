// Cloudflare Worker that routes compact soul break permalinks and injects
// per-link Open Graph / Twitter embed tags.
//
//   /20210006          -> single soul break
//   /m/?ids=1&ids=2    -> multiple soul breaks
//
// Neither path exists as a file on the static origin (GitHub Pages), so this
// Worker resolves them: it serves the /view.html renderer template under the
// pretty URL and rewrites the <head> so embeds reflect the referenced soul
// breaks. Embed crawlers (Discord, Twitter, Slack) never run JavaScript, so
// this server-side rewrite is the only way the unfurl can vary per link.
// Everything else (/, /search, /static, /data, /view.html) passes straight
// through to the origin.
//
// Deploy: see worker/README.md.

// The static origin behind the Worker. Overridable via the ORIGIN var (see
// wrangler.toml) so `wrangler dev` can point at a local static server.
const DEFAULT_ORIGIN = 'https://ffrk.xyz';

// Match static/sb-ids.js.
function parseIds(searchParams) {
  const ids = [];
  const seen = new Set();
  for (const raw of searchParams.getAll('ids')) {
    for (const id of raw.split(',')) {
      const trimmed = id.trim();
      if (trimmed && !seen.has(trimmed)) {
        seen.add(trimmed);
        ids.push(trimmed);
      }
    }
  }
  return ids;
}

// Returns the referenced ids if this path is a permalink, else null (passthrough).
function refIds(url) {
  const single = /^\/(\d+)\/?$/.exec(url.pathname);
  if (single) return [single[1]];
  if (url.pathname === '/m' || url.pathname === '/m/') return parseIds(url.searchParams);
  return null;
}

function attr(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

let cachedItems = null;
async function loadItems(origin) {
  if (cachedItems) return cachedItems;
  const resp = await fetch(`${origin}/data/all.json`, { cf: { cacheTtl: 3600, cacheEverything: true } });
  const data = await resp.json();
  const store = {};
  for (const item of data.items) store[item.id] = item;
  cachedItems = store;
  return store;
}

function buildMeta(found) {
  let title, description, image;

  if (found.length === 1) {
    const sb = found[0];
    title = `${sb.character} ${sb.sb_version} - ${sb.name}`;
    const attrs = [
      (sb.elements || []).join(', '),
    ].filter(Boolean);
    const attrLine = attrs.join(' · ');
    description = attrLine ? `${attrLine}\n${sb.description}` : sb.description;
    image = sb.image_url;
  } else {
    title = `${found.length} soul breaks`;
    description = found
      .slice(0, 12)
      .map(sb => `${sb.character} ${sb.sb_version} — ${sb.name}`)
      .join('\n');
    if (found.length > 12) description += `\n…and ${found.length - 12} more`;
    image = found[0].image_url;
  }

  // twitter:card isn't just for Twitter — Discord/Slack read it to pick a large
  // image vs. a small thumbnail. The other twitter:* tags are redundant with the
  // og: ones (consumers only fall back to them when og: is absent), so we omit
  // them and let og:title/description/image do the work.
  const card = found.length === 1 ? 'summary_large_image' : 'summary';
  let tags = `
    <meta property="og:title" content="${attr(title)}">
    <meta property="og:description" content="${attr(description)}">
    <meta name="twitter:card" content="${card}">`;
  if (image) {
    tags += `
    <meta property="og:image" content="${attr(image)}">`;
  }
  return { title, tags };
}

class HeadRewriter {
  constructor(meta) { this.meta = meta; }
  element(head) { head.append(this.meta.tags, { html: true }); }
}

class TitleRewriter {
  constructor(meta) { this.meta = meta; }
  element(title) { title.setInnerContent(this.meta.title); }
}

class RemoveElement {
  element(el) { el.remove(); }
}

// Static fallback tags in view.html that buildMeta re-emits. We strip these
// before appending the dynamic set so the page has exactly one of each —
// crawlers disagree on whether the first or last duplicate wins. og:site_name
// and og:type are left intact (the Worker doesn't re-emit them).
const OVERRIDDEN_META = [
  'meta[property="og:title"]',
  'meta[property="og:description"]',
  'meta[property="og:image"]',
  'meta[name="twitter:card"]',
];

export default {
  async fetch(request, env) {
    const origin = (env && env.ORIGIN) || DEFAULT_ORIGIN;
    const toOrigin = path => new URL(path, origin).toString();
    const url = new URL(request.url);
    const ids = refIds(url);

    // Not a permalink — pass through to the static origin (GitHub Pages, or a
    // local server under `wrangler dev`), preserving method/headers/body.
    if (ids === null) {
      return fetch(new Request(toOrigin(url.pathname + url.search), request));
    }

    // Serve the renderer template under the pretty URL, enriched with embed
    // tags. On any failure, still serve the template so humans see the page.
    const template = fetch(toOrigin('/view.html'), { cf: { cacheTtl: 300, cacheEverything: true } });
    try {
      const [templateResp, store] = await Promise.all([template, loadItems(origin)]);
      const found = ids.map(id => store[id]).filter(Boolean);

      // No known ids: leave the static fallback tags in place.
      if (found.length === 0) return new Response(templateResp.body, templateResp);

      const meta = buildMeta(found);
      let rewriter = new HTMLRewriter()
        .on('head', new HeadRewriter(meta))
        .on('title', new TitleRewriter(meta));
      for (const sel of OVERRIDDEN_META) rewriter = rewriter.on(sel, new RemoveElement());
      return rewriter.transform(templateResp);
    } catch (e) {
      return fetch(toOrigin('/view.html'));
    }
  },
};
