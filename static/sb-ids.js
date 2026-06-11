// Shared soul break id helpers, used by the renderer, the search page, and
// (mirrored) the Cloudflare Worker.
//
// URL scheme:
//   /20210006            single soul break  (compact, the common share case)
//   /m/?ids=1&ids=2      multiple            (also accepts ?ids=1,2)

// Parse the `ids` query params from a search string. Supports repeated params
// and comma lists, de-duplicated while preserving order.
function parseIds(search) {
  const params = new URLSearchParams(search);
  const ids = [];
  const seen = new Set();
  for (const raw of params.getAll('ids')) {
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

// Resolve the referenced ids from a full location: a bare numeric path
// (/20210006) is a single soul break; otherwise read ?ids from the query.
function parseRef(pathname, search) {
  const single = /^\/(\d+)\/?$/.exec(pathname);
  if (single) return [single[1]];
  return parseIds(search);
}

// Build the shortest shareable URL for a set of ids.
function buildShareUrl(origin, ids) {
  if (ids.length === 1) return `${origin}/${ids[0]}`;
  const qs = ids.map(id => `ids=${encodeURIComponent(id)}`).join('&');
  return `${origin}/m/?${qs}`;
}
