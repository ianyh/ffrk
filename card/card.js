// Shared card builder. Used by card.html (one card, for headless screenshots)
// and gallery.html (an edge-case stress sheet). Keeping the markup in one place
// means both the screenshots and the design preview stay in sync.

// Primary-element accent, mirroring the palette the cards are designed around.
const ELEMENT_COLORS = {
  Fire: '#f06e5a', Ice: '#78c8eb', Lightning: '#c8aafa', Earth: '#c8a064',
  Wind: '#8cdcaa', Water: '#6eaaeb', Holy: '#f0e196', Dark: '#b48cd7',
  Poison: '#b482c8', NE: '#96a0b4',
};

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
}

// Build a .card element for one soul break. Returns { card, img } so callers can
// await the icon load before screenshotting. Accent is set on the card itself
// (not :root) so a gallery can show many cards with different accents.
function buildCard(sb) {
  const card = el('div', 'card');
  card.style.setProperty('--accent', ELEMENT_COLORS[sb.elements[0]] || ELEMENT_COLORS.NE);

  const img = el('img');
  img.src = sb.image_url;
  img.alt = '';
  const icon = el('div', 'icon');
  icon.append(img);

  const meta = el('div', 'meta');
  meta.append(el('div', 'character', sb.character), el('div', 'name', sb.name));

  const chips = el('div', 'chips');
  chips.append(el('span', 'chip version', sb.sb_version), el('span', 'chip', sb.realm));
  for (const element of sb.elements) chips.append(el('span', 'chip', element));
  meta.append(chips);

  const header = el('div', 'header');
  header.append(icon, meta);

  card.append(header, el('hr'), el('div', 'desc', sb.description));
  return { card, img };
}

async function loadItems() {
  const data = await fetch('/data/all.json').then(r => r.json());
  return data.items;
}
