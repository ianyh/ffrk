// Shared card builder. Used by card.html (one card, for headless screenshots)
// and gallery.html (an edge-case stress sheet). Keeping the markup in one place
// means both the screenshots and the design preview stay in sync.

// Primary-element accent, mirroring the palette the cards are designed around.
const ELEMENT_COLORS = {
  Fire: '#f06e5a', Ice: '#78c8eb', Lightning: '#c8aafa', Earth: '#c8a064',
  Wind: '#8cdcaa', Water: '#6eaaeb', Holy: '#f0e196', Dark: '#b48cd7',
  Poison: '#b482c8', NE: '#96a0b4',
};

// Accent (left bar, character label, version chip) keyed off the soul break
// type: PHY = physical, NAT = general / non-attack effects, everything else
// (BLK/WHT/SUM/…) = magic. Normalized for stray case + whitespace in the data.
const TYPE_COLORS = {
  PHY: '#ef9259',   // physical
  NAT: '#74c98a',   // general effects (buffs/heals, not attacks)
};
const MAGIC_ACCENT = '#8b9bf5';

function accentFor(type) {
  return TYPE_COLORS[(type || '').trim().toUpperCase()] || MAGIC_ACCENT;
}

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
  card.style.setProperty('--accent', accentFor(sb.type));

  const img = el('img');
  img.src = sb.image_url;
  img.alt = '';
  const icon = el('div', 'icon');
  icon.append(img);

  // Lead with character + version (what people identify by); name is a subtitle.
  const meta = el('div', 'meta');
  const title = el('div', 'title');
  title.append(el('span', 'character', sb.character), el('span', 'version', sb.sb_version));
  const chips = el('div', 'chips');
  chips.append(el('span', 'chip', sb.type), el('span', 'chip', sb.target));
  meta.append(title, el('div', 'name', sb.name), chips);

  const header = el('div', 'header');
  header.append(icon, meta);

  // Element chips live in the footer, colored by element, beside the brand.
  const footer = el('div', 'footer');
  const elementChips = el('div', 'chips');
  for (const element of sb.elements) {
    const chip = el('span', 'chip', element);
    chip.style.background = ELEMENT_COLORS[element] || ELEMENT_COLORS.NE;
    chip.style.color = 'var(--bg)';
    elementChips.append(chip);
  }
  footer.append(elementChips);//, el('span', 'brand', 'ffrk.xyz'));

  card.append(header, el('hr'), el('div', 'desc', sb.description), footer);
  return { card, img };
}

async function loadItems() {
  const data = await fetch('/data/all.json').then(r => r.json());
  return data.items;
}
