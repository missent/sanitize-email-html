/**
 * missent Email HTML Sanitization & Plain Text Formatting
 *
 * Ensures safe, clean rendering of Gmail messages.
 * - Strips scripts, forms, iframes, and active/executable code
 * - Strips event handlers and javascript: URLs
 * - Isolates email content on a natural light/white canvas with readable text
 * - Constrains images (max-width: 100%, height: auto) to prevent blown up layouts
 * - Preserves email layout tables without artificial borders or broken nested layouts
 * - Ensures external links have target="_blank" and rel="noreferrer noopener"
 * - Restricts image URLs to safe https/http/data:image protocols
 * - Preserves safe sender-specified colors, font families, text alignments, and spacing
 * - Never rewrites sender text colors: email renders exactly as sent
 * - Rejects dangerous CSS patterns: url(), @import, expressions, behaviors, escape positioning, z-index
 */

const ALLOWED_TAGS = new Set([
  'a',
  'abbr',
  'address',
  'article',
  'b',
  'bdi',
  'bdo',
  'blockquote',
  'br',
  'caption',
  'cite',
  'code',
  'col',
  'colgroup',
  'dd',
  'del',
  'details',
  'dfn',
  'div',
  'dl',
  'dt',
  'em',
  'figcaption',
  'figure',
  'font',
  'footer',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'i',
  'img',
  'ins',
  'kbd',
  'li',
  'main',
  'mark',
  'ol',
  'p',
  'pre',
  'q',
  'rp',
  'rt',
  'ruby',
  's',
  'samp',
  'section',
  'small',
  'span',
  'strike',
  'strong',
  'sub',
  'summary',
  'sup',
  'table',
  'tbody',
  'td',
  'tfoot',
  'th',
  'thead',
  'time',
  'tr',
  'u',
  'ul',
  'var',
  'wbr',
  'center',
]);

const DANGEROUS_TAGS = new Set([
  'script',
  'iframe',
  'frame',
  'frameset',
  'object',
  'embed',
  'applet',
  'form',
  'input',
  'button',
  'select',
  'textarea',
  'base',
  'link',
  'meta',
  'style',
  'svg',
  'math',
  'noscript',
  'template',
]);

const GLOBAL_ATTRIBUTES = new Set([
  'class',
  'style',
  'title',
  'dir',
  'lang',
  'align',
  'valign',
  'aria-hidden',
  'aria-label',
]);

const ALLOWED_ATTRIBUTES: Record<string, Set<string>> = {
  a: new Set(['href', 'title', 'target', 'rel', 'class', 'style', 'name']),
  img: new Set([
    'src',
    'alt',
    'title',
    'width',
    'height',
    'loading',
    'decoding',
    'align',
    'border',
    'hspace',
    'vspace',
    'class',
    'style',
  ]),
  table: new Set([
    'border',
    'cellpadding',
    'cellspacing',
    'width',
    'height',
    'align',
    'valign',
    'bgcolor',
    'background',
    'summary',
    'class',
    'style',
  ]),
  td: new Set([
    'colspan',
    'rowspan',
    'align',
    'valign',
    'width',
    'height',
    'bgcolor',
    'background',
    'nowrap',
    'class',
    'style',
  ]),
  th: new Set([
    'colspan',
    'rowspan',
    'align',
    'valign',
    'width',
    'height',
    'bgcolor',
    'background',
    'nowrap',
    'scope',
    'class',
    'style',
  ]),
  tr: new Set(['align', 'valign', 'bgcolor', 'class', 'style']),
  tbody: new Set(['align', 'valign', 'bgcolor', 'class', 'style']),
  thead: new Set(['align', 'valign', 'bgcolor', 'class', 'style']),
  tfoot: new Set(['align', 'valign', 'bgcolor', 'class', 'style']),
  col: new Set(['span', 'width', 'align', 'valign', 'class', 'style']),
  colgroup: new Set(['span', 'width', 'align', 'valign', 'class', 'style']),
  font: new Set(['color', 'size', 'face', 'class', 'style']),
  hr: new Set(['align', 'width', 'size', 'color', 'noshade', 'class', 'style']),
  ol: new Set(['start', 'type', 'reversed', 'class', 'style']),
  ul: new Set(['type', 'class', 'style']),
  li: new Set(['value', 'class', 'style']),
  blockquote: new Set(['cite', 'class', 'style']),
  time: new Set(['datetime', 'class', 'style']),
  div: new Set(['align', 'valign', 'class', 'style']),
  p: new Set(['align', 'class', 'style']),
  h1: new Set(['align', 'class', 'style']),
  h2: new Set(['align', 'class', 'style']),
  h3: new Set(['align', 'class', 'style']),
  h4: new Set(['align', 'class', 'style']),
  h5: new Set(['align', 'class', 'style']),
  h6: new Set(['align', 'class', 'style']),
  center: new Set(['class', 'style']),
};

const SAFE_CSS_PROPERTIES = new Set([
  'color',
  'background',
  'background-color',
  'font',
  'font-family',
  'font-size',
  'font-weight',
  'font-style',
  'font-variant',
  'line-height',
  'text-align',
  'text-decoration',
  'text-transform',
  'text-indent',
  'letter-spacing',
  'word-spacing',
  'word-break',
  'overflow-wrap',
  'white-space',
  'margin',
  'margin-top',
  'margin-right',
  'margin-bottom',
  'margin-left',
  'padding',
  'padding-top',
  'padding-right',
  'padding-bottom',
  'padding-left',
  'border',
  'border-top',
  'border-right',
  'border-bottom',
  'border-left',
  'border-color',
  'border-style',
  'border-width',
  'border-radius',
  'border-collapse',
  'border-spacing',
  'width',
  'min-width',
  'max-width',
  'height',
  'min-height',
  'max-height',
  'vertical-align',
  'display',
  'box-sizing',
  'table-layout',
]);

const ALLOWED_DISPLAYS = new Set([
  'inline',
  'block',
  'inline-block',
  'table',
  'table-cell',
  'table-row',
  'table-column',
  'flex',
  'inline-flex',
  'grid',
  'inline-grid',
  'none',
]);

function isSafeUrl(url: string, allowDataImage = false): boolean {
  const trimmed = url.trim().toLowerCase();
  if (trimmed.startsWith('javascript:') || trimmed.startsWith('vbscript:')) {
    return false;
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('mailto:')) {
    return true;
  }
  if (allowDataImage && trimmed.startsWith('data:image/')) {
    return true;
  }
  return false;
}

/**
 * Parses a CSS color string to RGB numbers [r, g, b].
 */
export function parseColorToRgb(color: string): [number, number, number] | null {
  const c = color.trim().toLowerCase();
  if (c === 'black') return [0, 0, 0];
  if (c === 'white') return [255, 255, 255];
  if (c === 'transparent') return null;

  const hexMatch = c.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hexMatch) {
    const hex = hexMatch[1];
    if (hex.length === 3) {
      return [
        parseInt(hex[0] + hex[0], 16),
        parseInt(hex[1] + hex[1], 16),
        parseInt(hex[2] + hex[2], 16),
      ];
    }
    return [
      parseInt(hex.slice(0, 2), 16),
      parseInt(hex.slice(2, 4), 16),
      parseInt(hex.slice(4, 6), 16),
    ];
  }

  const rgbMatch = c.match(/^rgba?\s*\(\s*([0-9]{1,3})\s*,\s*([0-9]{1,3})\s*,\s*([0-9]{1,3})/i);
  if (rgbMatch) {
    return [
      Math.min(255, parseInt(rgbMatch[1], 10)),
      Math.min(255, parseInt(rgbMatch[2], 10)),
      Math.min(255, parseInt(rgbMatch[3], 10)),
    ];
  }

  return null;
}

/**
 * Returns standard WCAG relative luminance of an RGB triplet (0.0 to 1.0).
 */
export function getRelativeLuminance(r: number, g: number, b: number): number {
  const rs = r / 255;
  const gs = g / 255;
  const bs = b / 255;
  const rL = rs <= 0.03928 ? rs / 12.92 : Math.pow((rs + 0.055) / 1.055, 2.4);
  const gL = gs <= 0.03928 ? gs / 12.92 : Math.pow((gs + 0.055) / 1.055, 2.4);
  const bL = bs <= 0.03928 ? bs / 12.92 : Math.pow((bs + 0.055) / 1.055, 2.4);
  return 0.2126 * rL + 0.7152 * gL + 0.0722 * bL;
}

/**
 * Returns WCAG contrast ratio (1.0 to 21.0).
 */
export function getContrastRatio(rgb1: [number, number, number], rgb2: [number, number, number]): number {
  const l1 = getRelativeLuminance(...rgb1);
  const l2 = getRelativeLuminance(...rgb2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * Sanitizes CSS style attribute values.
 * Strictly removes url(), @import, expression(), behavior, positioning, z-index, animations.
 */
export function sanitizeCssStyle(css: string): string {
  if (!css || typeof css !== 'string') {
    return '';
  }

  // Comments are whitespace, never removed by concatenation (u/**/rl must
  // not turn into url). Escapes, control characters and unknown functions are
  // rejected per declaration: no URL/image-set/src/var/attr fetch or indirection.
  css = css.replace(/\/\*[\s\S]*?\*\//g, ' ');
  const safeDeclarations: string[] = [];
  for (const decl of css.split(';')) {
    const colon = decl.indexOf(':');
    if (colon < 0) continue;
    const prop = decl.slice(0, colon).trim().toLowerCase();
    const raw = decl.slice(colon + 1).trim();
    const important = /!important\s*$/i.test(raw);
    const val = raw.replace(/!important\s*$/i, '').trim();
    // The property allowlist is limited to typography, colors, spacing and
    // ordinary flow/table sizing. No positioning (including fixed/sticky),
    // z-index, transforms, animations, generated content, bindings, custom
    // properties or resource-bearing properties can affect surrounding chrome.
    if (!SAFE_CSS_PROPERTIES.has(prop) || !val) continue;
    if (/[\\{}<>@!\x00-\x1f\x7f]/.test(val) || /(?:url|expression|javascript|vbscript|behavior)\s*[:(]/i.test(val)) continue;
    // Only color functions are supported; reject all other functions even if
    // nested or unknown to this browser (future CSS must fail closed).
    if (val.replace(/(?:rgb|rgba|hsl|hsla)\([0-9.,%+\-\s/]*\)/gi, '').includes('(') ||
        val.replace(/(?:rgb|rgba|hsl|hsla)\([0-9.,%+\-\s/]*\)/gi, '').includes(')')) continue;
    if (prop === 'display' && !ALLOWED_DISPLAYS.has(val.toLowerCase())) continue;
    // No CSS-wide keyword special-cases here by design: `inherit` on these
    // properties computes from the same parent chain that implicit
    // inheritance already exposes, and `unset` behaves identically for them
    // — stripping one keyword while passing the other would buy no isolation
    // at pure fidelity cost. Isolation comes from selector scoping and class
    // namespacing, never from rewriting sender values.
    safeDeclarations.push(`${prop}: ${val}${important ? ' !important' : ''}`);
  }

  return safeDeclarations.join('; ');
}

// Sender class namespace: every sender class token is prefixed during
// sanitization (class="app-header" becomes class="snd-app-header") so no
// chrome class selector can ever match email content. Sender <style> class
// selectors are rewritten to the same prefixed form below, composing with
// the per-email scope class. Classes the sanitizer itself adds
// (email-body-*, email-table-*, email-scope-*) are attached after the rename
// and stay unprefixed by design.
export const SENDER_CLASS_PREFIX = 'snd-';

// Sanitizer-owned bare class for the inner body-replacement element, in the
// same family as email-body-link / email-body-image / email-body-table:
// attached directly (never namespaced), so sender `.email-body` rules —
// rewritten to `.snd-email-body` like any sender class — cannot collide.
export const BODY_REPLACEMENT_CLASS = 'email-body';

function namespaceSenderClassAttribute(el: Element): void {
  const raw = el.getAttribute('class');
  if (raw === null) return;
  const namespaced = raw
    .split(/\s+/)
    .filter(Boolean)
    .map((token) => `${SENDER_CLASS_PREFIX}${token}`);
  if (namespaced.length > 0) {
    el.setAttribute('class', namespaced.join(' '));
  } else {
    el.removeAttribute('class');
  }
}

/** Rewrite sender stylesheet class selectors to the namespaced form. */
function namespaceSelectorClasses(selector: string): string {
  return selector.replace(/\.([a-zA-Z_][a-zA-Z0-9_-]*)/g, `.${SENDER_CLASS_PREFIX}$1`);
}

// Restricted stylesheet grammar: only ordinary style rules and width media
// queries. No @import, @font-face, @supports, @layer, @page, keyframes or nesting.
// Parsing blocks before declarations prevents malformed CSS from escaping a
// scoped rule. Quotes/comments are tracked so braces inside strings are inert.
let emailScopeSequence = 0;
function sanitizeStylesheet(css: string, scope: string, depth = 0): string {
  if (depth > 4) return ''; // Bound nesting work for hostile input.
  css = css.replace(/\/\*[\s\S]*?\*\//g, ' ');
  let start = 0;
  let quote = '';
  let level = 0;
  let open = -1;
  const output: string[] = [];
  for (let i = 0; i < css.length; i++) {
    const ch = css[i];
    if (ch === '\\') { i++; continue; }
    if (quote) { if (ch === quote) quote = ''; continue; }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === ';' && level === 0) { start = i + 1; continue; }
    if (ch === '{') { if (level++ === 0) open = i; }
    if (ch !== '}' || level === 0 || --level !== 0) continue;
    const header = css.slice(start, open).trim();
    const body = css.slice(open + 1, i);
    start = i + 1;
    // Screen/all and min/max-width in px/em/rem cover common marketing
    // breakpoints. No arbitrary conditions, selector queries or other at-rules.
    if (/^@media\s+(?:(?:only\s+)?(?:screen|all)\s+and\s+)?\((?:min-|max-)?width\s*:\s*\d+(?:\.\d+)?(?:px|em|rem)\)(?:\s+and\s+\((?:min-|max-)?width\s*:\s*\d+(?:\.\d+)?(?:px|em|rem)\))*$/i.test(header)) {
      const rules = sanitizeStylesheet(body, scope, depth + 1);
      if (rules) output.push(`${header} { ${rules} }`);
      continue;
    }
    const selectors = header.split(',').map(value => value.trim());
    // Simple ASCII element/class selectors with descendant/child combinators
    // only. Reject IDs (HTML IDs are stripped), attributes, pseudo selectors,
    // escapes, siblings and nesting so no selector can climb out of the scope.
    const compound = /^(?:[a-zA-Z][a-zA-Z0-9-]*|\*)?(?:\.[a-zA-Z_][a-zA-Z0-9_-]*)*$/;
    // Tokenize combinators rather than a nested optional regex, avoiding
    // pathological backtracking on attacker-controlled long selectors.
    if (/[{}]/.test(body) || selectors.some(value =>
      !value || value.length > 2048 || value.split('>').some(part =>
        !part.trim() || part.trim().split(/\s+/).some(token => !compound.test(token))))) continue;
    const declarations = sanitizeCssStyle(body);
    if (!declarations) continue;
    const scoped = selectors.map(value => {
      // `body` (after an optional `html`, with optional class compounds such
      // as `body.newsletter`) ALWAYS denotes the inner body-replacement
      // element, which is emitted unconditionally whenever scoped styles
      // exist — the mapping no longer branches on body-class presence, so
      // `body`, `body > .x`, and `body.a .x` mean the same element in every
      // email. Bare `html` still maps to the scope wrapper, as before.
      // Class tokens are prefixed before the bare replacement class is
      // attached, so a sender `.email-body` rule still lands namespaced.
      // The `html` prefix accepts whitespace or a child combinator
      // (`html body`, `html>body`, `html > body`) — but never a bare
      // `htmlbody` element name, which keeps failing closed as nonexistent.
      const bodyLead = value.match(/^(?:html(?:\s+|\s*>\s*))?body((?:\.[a-zA-Z_][a-zA-Z0-9_-]*)*)(?=[\s>]|$)/i);
      let base = scope;
      let rest: string;
      if (bodyLead) {
        base = `${scope} .${BODY_REPLACEMENT_CLASS}${namespaceSelectorClasses(bodyLead[1])}`;
        rest = value.slice(bodyLead[0].length).trim();
      } else {
        // HTML/body wrappers are discarded by DOMParser; map a leading bare
        // `html` to our message wrapper without granting access to the canvas.
        rest = value.replace(/^html(?=[\s>]|$)/i, '').trim();
      }
      // Class selectors target the renamed sender classes, keeping sender
      // stylesheets working inside the namespace. Compound (.a.b),
      // descendant (.a .b), and child (.a > .b) forms rewrite uniformly
      // because every class token is prefixed.
      const namespaced = namespaceSelectorClasses(rest);
      return namespaced ? `${base} ${namespaced}` : base;
    });
    output.push(`${scoped.join(', ')} { ${declarations} }`);
  }
  return output.join('\n');
}

/**
 * Sanitizes HTML content from an email body for safe browser rendering.
 * Isolates content for presentation on a white document canvas.
 */
export function sanitizeEmailHtml(rawHtml: string): string {
  if (!rawHtml || typeof rawHtml !== 'string') {
    return '';
  }

  // Use browser DOMParser
  const parser = new DOMParser();
  const doc = parser.parseFromString(rawHtml, 'text/html');

  // Read head AND body styles before removing originals and all attributes.
  // Sanitized CSS is emitted as text only, never interpolated from raw HTML.
  const scopeClass = `email-scope-${++emailScopeSequence}`;
  const scope = `.email-canvas .${scopeClass}`;
  const sheets = Array.from(doc.querySelectorAll('style')).map(el => {
    // Preserve supported style-level media restrictions rather than making
    // print-only or unsupported sheets apply unconditionally.
    const media = el.getAttribute('media');
    const css = el.textContent || '';
    return sanitizeStylesheet(media ? `@media ${media} { ${css} }` : css, scope);
  }).filter(Boolean).join('\n');

  // Remove dangerous tags first
  const dangerousElements = doc.querySelectorAll(Array.from(DANGEROUS_TAGS).join(', '));
  dangerousElements.forEach((el) => el.remove());

  // Clean all elements recursively
  const allElements = Array.from(doc.body.querySelectorAll('*'));
  for (const el of allElements) {
    const tagName = el.tagName.toLowerCase();

    // If tag is not allowed, unwrap children or remove
    if (!ALLOWED_TAGS.has(tagName)) {
      el.replaceWith(...Array.from(el.childNodes));
      continue;
    }

    // Clean attributes
    const allowedForTag = ALLOWED_ATTRIBUTES[tagName];
    const attributesToRemove: string[] = [];

    for (let i = 0; i < el.attributes.length; i++) {
      const attr = el.attributes[i];
      const attrName = attr.name.toLowerCase();
      const attrValue = attr.value;

      // Disallow event handlers
      if (attrName.startsWith('on')) {
        attributesToRemove.push(attr.name);
        continue;
      }

      // Check if attribute is allowed
      const isAllowed =
        GLOBAL_ATTRIBUTES.has(attrName) ||
        (allowedForTag && allowedForTag.has(attrName));

      if (!isAllowed) {
        attributesToRemove.push(attr.name);
        continue;
      }

      // Check specific attributes
      if (attrName === 'href') {
        if (!isSafeUrl(attrValue)) {
          attributesToRemove.push(attr.name);
        }
      } else if (attrName === 'src' || attrName === 'background') {
        if (!isSafeUrl(attrValue, true)) {
          attributesToRemove.push(attr.name);
        }
      } else if (attrName === 'style') {
        const sanitized = sanitizeCssStyle(attrValue);
        if (sanitized) {
          el.setAttribute('style', sanitized);
        } else {
          attributesToRemove.push(attr.name);
        }
      }
    }

    for (const name of attributesToRemove) {
      el.removeAttribute(name);
    }

    // Namespace sender classes before the sanitizer attaches its own below,
    // so chrome class selectors can never match email content while
    // sanitizer-added classes (email-body-*, email-table-*) stay bare.
    namespaceSenderClassAttribute(el);

    // Incoming-email authenticity: sender text colors are never rewritten.
    // A low-contrast sender combination (e.g. white text on a pale card)
    // renders exactly as sent; no fallback color is invented here.

    // Enforce link security and styling
    if (tagName === 'a') {
      el.setAttribute('target', '_blank');
      el.setAttribute('rel', 'noreferrer noopener');
      el.classList.add('email-body-link');
    }

    // Enhance images for responsiveness and graceful failure
    if (tagName === 'img') {
      if (!el.hasAttribute('loading')) {
        el.setAttribute('loading', 'lazy');
      }
      if (!el.hasAttribute('alt')) {
        el.setAttribute('alt', '');
      }
      el.classList.add('email-body-image');
    }

    // Tag tables
    if (tagName === 'table') {
      el.classList.add('email-body-table');
    }
  }

  // HTML presentation attributes lose to the canvas CSS reset. Translate only
  // bounded numeric spacing, preserving explicit safe inline sender styles.
  for (const table of Array.from(doc.body.querySelectorAll('table'))) {
    const spacing = (name: string) => {
      const value = table.getAttribute(name);
      return value !== null && /^\d{1,3}$/.test(value) && Number(value) <= 256 ? `${Number(value)}px` : null;
    };
    const gap = spacing('cellspacing');
    if (gap && !table.style.borderSpacing) table.style.borderSpacing = gap;
    const padding = spacing('cellpadding');
    if (padding) for (const cell of Array.from(table.querySelectorAll<HTMLElement>('td, th'))) {
      if (cell.closest('table') !== table) continue;
      for (const side of ['paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft'] as const) {
        if (!cell.style[side]) cell.style[side] = padding;
      }
    }
  }

  // Wrap ONLY outermost/top-level tables that are not nested inside another table
  // to avoid breaking nested layout table rendering.
  // If the table is centered (via align="center" or inside a <center>), ensure the wrapper preserves centering.
  const tables = Array.from(doc.body.querySelectorAll('table'));
  for (const table of tables) {
    if (table.parentElement?.closest('table')) continue;
    if (table.parentElement?.classList.contains('email-table-container')) continue;
    const wrapper = doc.createElement('div');
    wrapper.className = 'email-table-container';
    const hasExplicitAlign = table.getAttribute('align')?.toLowerCase();
    const isCentered =
      hasExplicitAlign === 'center' ||
      (!hasExplicitAlign && (
        table.closest('center') !== null ||
        table.closest('[align="center"]') !== null ||
        Boolean(table.closest('[style*="text-align: center"], [style*="text-align:center"]'))
      ));
    if (isCentered) {
      wrapper.style.textAlign = 'center';
      table.classList.add('email-table--centered');
    }
    table.parentNode?.insertBefore(wrapper, table);
    wrapper.appendChild(table);
  }

  // The sender's <body> presentation attributes/styles belong to the message,
  // but only body children are returned below. Carry safe body presentation
  // onto the output wrapper so it is not silently dropped.
  //
  // Precedence mechanism: in real browsers legacy presentational attributes
  // have specificity 0 and ALWAYS lose to inline styles, so the attributes
  // are only translated into CSS for properties the sender's own inline
  // style does not already define. Appending them unconditionally would
  // reverse browser precedence and let e.g. bgcolor override an explicit
  // background-color. Resource-bearing attributes (background) and
  // link-color attributes are dropped for security.
  const bodyStyle = doc.body.getAttribute('style');
  const sanitizedBodyStyle = bodyStyle ? sanitizeCssStyle(bodyStyle) : '';
  // Property set already claimed by the explicit inline style. `background`
  // shorthand covers background-color; each other property stands alone.
  const inlineProps = new Set(
    sanitizedBodyStyle
      .split(';')
      .map((decl) => decl.slice(0, decl.indexOf(':')).trim().toLowerCase())
      .filter(Boolean),
  );
  const bodyPresentation: string[] = [];
  if (sanitizedBodyStyle) bodyPresentation.push(sanitizedBodyStyle);
  const bodyBg = doc.body.getAttribute('bgcolor');
  if (
    bodyBg &&
    /^(?:#[0-9a-f]{3}(?:[0-9a-f]{3})?|[a-z]+)$/i.test(bodyBg.trim()) &&
    !inlineProps.has('background-color') &&
    !inlineProps.has('background')
  ) {
    bodyPresentation.push(`background-color: ${bodyBg.trim()}`);
  }
  const bodyText = doc.body.getAttribute('text');
  if (
    bodyText &&
    /^(?:#[0-9a-f]{3}(?:[0-9a-f]{3})?|[a-z]+)$/i.test(bodyText.trim()) &&
    !inlineProps.has('color')
  ) {
    bodyPresentation.push(`color: ${bodyText.trim()}`);
  }
  const bodyAlign = doc.body.getAttribute('align');
  if (
    bodyAlign &&
    /^(?:left|center|right|justify)$/i.test(bodyAlign.trim()) &&
    !inlineProps.has('text-align')
  ) {
    bodyPresentation.push(`text-align: ${bodyAlign.trim().toLowerCase()}`);
  }
  const bodyStyleAttr = bodyPresentation.length > 0 ? bodyPresentation.join('; ') : null;

  if (sheets) {
    const wrapper = doc.createElement('div');
    wrapper.className = scopeClass;
    // The sender <body> element itself is discarded (only its children are
    // returned), so every email gets an unconditional inner body-replacement
    // div: the rewriter maps `body` to this element in all cases, and
    // descendant combinators (`.snd-newsletter .snd-label`) need the outer
    // classes on a true ancestor of the content. It carries the sanitizer-
    // owned bare class plus the tokenized, prefixed body classes (when any),
    // as well as the translated body presentation — style and classes share
    // this one element so the native cascade holds (inline style beats class
    // rules here; children inherit the winner). The outer scope wrapper
    // keeps only the scope class. (Without scoped styles there is nothing to
    // map, so the plain-style branch below keeps its bare wrapper.)
    const bodyReplacement = doc.createElement('div');
    bodyReplacement.classList.add(BODY_REPLACEMENT_CLASS);
    const bodyClass = doc.body.getAttribute('class');
    if (bodyClass) {
      const namespacedBodyClasses = bodyClass
        .split(/\s+/)
        .filter(Boolean)
        .map((token) => `${SENDER_CLASS_PREFIX}${token}`);
      if (namespacedBodyClasses.length > 0) bodyReplacement.classList.add(...namespacedBodyClasses);
    }
    if (bodyStyleAttr) bodyReplacement.setAttribute('style', bodyStyleAttr);
    wrapper.append(bodyReplacement);
    bodyReplacement.append(...Array.from(doc.body.childNodes));
    const style = doc.createElement('style');
    style.textContent = sheets;
    doc.body.append(style, wrapper);
  } else if (bodyStyleAttr) {
    const wrapper = doc.createElement('div');
    wrapper.setAttribute('style', bodyStyleAttr);
    wrapper.append(...Array.from(doc.body.childNodes));
    doc.body.append(wrapper);
  }
  return doc.body.innerHTML.trim();
}

/**
 * Safely format plain-text email content by escaping HTML and auto-linking URLs.
 */
export function formatPlainTextEmail(text: string): string {
  if (!text || typeof text !== 'string') {
    return '';
  }

  // Escape HTML entities
  const escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  // Auto-link URLs
  const urlRegex = /(https?:\/\/[^\s<]+[^<.,:;"')\]\s])/g;
  const linked = escaped.replace(
    urlRegex,
    '<a href="$1" target="_blank" rel="noreferrer noopener" class="email-body-link">$1</a>',
  );

  // Wrap paragraphs in <p> tags
  const paragraphs = linked.split(/\n\s*\n/);
  return paragraphs
    .map((p) => `<p>${p.replace(/\n/g, '<br />')}</p>`)
    .join('\n');
}
