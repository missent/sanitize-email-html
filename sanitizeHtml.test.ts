import { describe, expect, it } from 'vitest';
import {
  formatPlainTextEmail,
  getContrastRatio,
  parseColorToRgb,
  sanitizeCssStyle,
  sanitizeEmailHtml,
} from './sanitizeHtml';

describe('sanitizeEmailHtml', () => {
  it('strips script tags and executable code', () => {
    const input = '<p>Hello</p><script>alert("xss")</script><p>World</p>';
    const output = sanitizeEmailHtml(input);
    expect(output).not.toContain('<script>');
    expect(output).not.toContain('alert');
    expect(output).toContain('<p>Hello</p>');
    expect(output).toContain('<p>World</p>');
  });

  it('strips iframes and forms', () => {
    const input = '<div><iframe src="https://evil.example"></iframe><form action="/steal"><button>Submit</button></form>Safe text</div>';
    const output = sanitizeEmailHtml(input);
    expect(output).not.toContain('<iframe');
    expect(output).not.toContain('<form');
    expect(output).not.toContain('<button');
    expect(output).toContain('Safe text');
  });

  it('strips event handler attributes like onclick and onerror', () => {
    const input = '<p onclick="alert(1)">Click</p><img src="https://example.com/pic.png" onerror="alert(2)" />';
    const output = sanitizeEmailHtml(input);
    expect(output).not.toContain('onclick');
    expect(output).not.toContain('onerror');
    expect(output).toContain('pic.png');
  });

  it('strips javascript: hrefs from links', () => {
    const input = '<a href="javascript:alert(1)">Evil link</a><a href="https://example.com">Good link</a>';
    const output = sanitizeEmailHtml(input);
    expect(output).not.toContain('javascript:');
    expect(output).toContain('href="https://example.com"');
    expect(output).toContain('target="_blank"');
    expect(output).toContain('rel="noreferrer noopener"');
  });

  it('preserves formatting: tables, lists, bold, italics, paragraphs', () => {
    const input = `
      <h1>Weekly Update</h1>
      <p>Here is the <strong>summary</strong> of <em>quarter 3</em>:</p>
      <ul>
        <li>Item 1</li>
        <li>Item 2</li>
      </ul>
      <table>
        <thead><tr><th>Col A</th><th>Col B</th></tr></thead>
        <tbody><tr><td>Val 1</td><td>Val 2</td></tr></tbody>
      </table>
    `;
    const output = sanitizeEmailHtml(input);
    expect(output).toContain('<h1>Weekly Update</h1>');
    expect(output).toContain('<strong>summary</strong>');
    expect(output).toContain('<em>quarter 3</em>');
    expect(output).toContain('<ul>');
    expect(output).toContain('<li>Item 1</li>');
    expect(output).toContain('<table');
    expect(output).toContain('<td>Val 1</td>');
  });

  it('preserves email layout attributes (bgcolor, cellpadding, cellspacing, width, align) without artificial grid lines', () => {
    const newsletterFixture = `
      <table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f4f4f4">
        <tr>
          <td align="center" valign="top">
            <table width="600" cellpadding="20" cellspacing="0" bgcolor="#ffffff">
              <tr>
                <td style="font-family: Arial, sans-serif; font-size: 16px; color: #333333;">
                  <h2>Willow Voice Weekly Digest</h2>
                  <p>Welcome to your audio transcription digest.</p>
                  <img src="https://example.com/header.png" width="560" alt="Banner" />
                  <p><a href="https://example.com/digest">Read online</a></p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    `;
    const output = sanitizeEmailHtml(newsletterFixture);

    // Attributes preserved on outer layout table
    expect(output).toContain('cellpadding="0"');
    expect(output).toContain('cellspacing="0"');
    expect(output).toContain('bgcolor="#f4f4f4"');
    expect(output).toContain('border="0"');

    // Attributes preserved on inner layout table
    expect(output).toContain('cellpadding="20"');
    expect(output).toContain('bgcolor="#ffffff"');

    // Image receives lazy loading and class
    expect(output).toContain('class="email-body-image"');
    expect(output).toContain('loading="lazy"');

    // Link receives security attributes
    expect(output).toContain('target="_blank"');
    expect(output).toContain('rel="noreferrer noopener"');

    // Outermost table is wrapped in scroll container, but inner nested table is NOT wrapped in a separate div
    expect(output).toContain('<div class="email-table-container"><table');
    const parser = new DOMParser();
    const doc = parser.parseFromString(output, 'text/html');
    const containers = doc.querySelectorAll('.email-table-container');
    expect(containers.length).toBe(1);
  });

  it('preserves https and data:image images, applies loading lazy', () => {
    const input = '<img src="https://example.com/logo.png" alt="Logo" /><img src="data:image/png;base64,iVBORw0KGgo=" alt="Inline" />';
    const output = sanitizeEmailHtml(input);
    expect(output).toContain('src="https://example.com/logo.png"');
    expect(output).toContain('src="data:image/png;base64,iVBORw0KGgo="');
    expect(output).toContain('loading="lazy"');
  });

  it('sanitizes dangerous CSS in style attributes', () => {
    const input = '<div style="color: red; position: fixed; background: expression(alert(1))">Content</div>';
    const output = sanitizeEmailHtml(input);
    expect(output).not.toContain('position: fixed');
    expect(output).not.toContain('expression');
    expect(output).toContain('color: red');
  });

  it('preserves text alignment and centered tables', () => {
    const input = `
      <div align="center">
        <table align="center" width="600">
          <tr>
            <td align="center">
              <p align="center">Centered Announcement</p>
            </td>
          </tr>
        </table>
      </div>
    `;
    const output = sanitizeEmailHtml(input);
    expect(output).toContain('align="center"');
    expect(output).toContain('text-align: center');
  });

  it('preserves sender text colors exactly as sent, without contrast rewriting', () => {
    // 1. Dark/blue text on pale-blue card (#e8f0fe): preserved
    const readableCard = '<div style="background-color: #e8f0fe;"><p style="color: #1a73e8;">Notice info</p></div>';
    const outReadable = sanitizeEmailHtml(readableCard);
    expect(outReadable).toContain('color: #1a73e8');

    // 2. White text on pale-blue card: low contrast, but authenticity wins —
    // the sender color is preserved exactly as sent, never rewritten.
    const paleCard = '<div style="background-color: #e8f0fe;"><p style="color: #ffffff;">Sender text</p></div>';
    const outPale = sanitizeEmailHtml(paleCard);
    expect(outPale).toContain('color: #ffffff');
    expect(outPale).not.toContain('color: #1f2328');
  });

  it('preserves white text on dark backgrounds', () => {
    const darkBanner = '<div style="background-color: #003366;"><p style="color: #ffffff;">Dark Banner Headline</p></div>';
    const output = sanitizeEmailHtml(darkBanner);
    expect(output).toContain('background-color: #003366');
    expect(output).toContain('color: #ffffff');
  });

  it('preserves stylesheet-defined dark panels and light text without alteration', () => {
    // Regression guard for the old contrast rewriter, which only saw inline
    // backgrounds and could flip white text on a stylesheet-defined dark
    // panel to dark. Sender styling now passes through untouched.
    const panel = '<style>.panel { background-color: #1a1a2e; } .panel p { color: #ffffff; }</style><div class="panel"><p>Night panel note</p></div>';
    const output = sanitizeEmailHtml(panel);
    expect(output).toContain('color: #ffffff');
    expect(output).not.toContain('color: #1f2328');
  });

  it('strictly blocks dangerous CSS patterns: url(), @import, animation, transition, and z-index', () => {
    const maliciousCss = `
      color: #333333;
      background-image: url('https://tracker.example/pixel.png');
      @import url('https://fonts.example/font.css');
      z-index: 999999;
      animation: pulse 1s infinite;
      position: sticky;
      --evil-var: red;
      font-size: 14px;
    `;
    const sanitized = sanitizeCssStyle(maliciousCss);
    expect(sanitized).not.toContain('url(');
    expect(sanitized).not.toContain('@import');
    expect(sanitized).not.toContain('z-index');
    expect(sanitized).not.toContain('animation');
    expect(sanitized).not.toContain('position');
    expect(sanitized).not.toContain('--evil-var');
    expect(sanitized).toContain('color: #333333');
    expect(sanitized).toContain('font-size: 14px');
  });

  it('preserves safe sender body presentation instead of dropping it with the body tag', () => {
    const output = sanitizeEmailHtml(
      '<html><head></head><body bgcolor="#f4f4f4" text="#222222" style="font-family: Arial, sans-serif; position: fixed;"><p>Fixture</p></body></html>',
    );
    expect(output).toContain('background-color: #f4f4f4');
    expect(output).toContain('color: #222222');
    expect(output).toContain('font-family: Arial, sans-serif');
    expect(output).not.toContain('position: fixed');
    expect(output).toContain('<p>Fixture</p>');
  });

  it('gives the sender inline style precedence over legacy body attributes', () => {
    // Browsers give presentational attributes specificity 0: they always lose
    // to inline styles. The translation must preserve that precedence.
    const output = sanitizeEmailHtml(
      '<html><head></head><body bgcolor="#111111" text="#222222" align="right" style="background-color: #ffffff; color: #333333; text-align: left;"><p>Fixture</p></body></html>',
    );
    expect(output).toContain('background-color: #ffffff');
    expect(output).toContain('color: #333333');
    expect(output).toContain('text-align: left');
    expect(output).not.toContain('#111111');
    expect(output).not.toContain('#222222');
    expect(output).not.toContain('text-align: right');
    expect(output).toContain('<p>Fixture</p>');
  });

  it('still fills gaps where the inline style leaves a property undefined', () => {
    const output = sanitizeEmailHtml(
      '<html><head></head><body bgcolor="#f4f4f4" style="color: #333333;"><p>Fixture</p></body></html>',
    );
    // No background declared inline, so the attribute value carries over;
    // the explicit inline color is kept and no attribute color is invented.
    expect(output).toContain('background-color: #f4f4f4');
    expect(output).toContain('color: #333333');
  });

  it('namespaces sender classes so chrome selectors cannot match email content', () => {
    const output = sanitizeEmailHtml('<div class="app-header">Fixture</div><span class="a b">More</span>');
    expect(output).toContain('class="snd-app-header"');
    expect(output).toContain('class="snd-a snd-b"');
    expect(output).not.toContain('class="app-header"');
  });

  it('strips sender id attributes so chrome #id selectors cannot match', () => {
    // styles.css has a single chrome #id rule (#inbox-heading); sender ids
    // never survive sanitization, and fragment/url(#) references are
    // rejected elsewhere, so no id namespacing is needed.
    const output = sanitizeEmailHtml('<div id="inbox-heading" class="x">Fixture</div>');
    expect(output).not.toContain('inbox-heading');
    expect(output).toContain('class="snd-x"');
  });

  it('rewrites sender stylesheet class selectors to the namespaced form', () => {
    const output = sanitizeEmailHtml(
      '<style>.panel { color: #1a73e8; } .a.b { color: #1a73e8; } .outer .inner { color: #1a73e8; } .par > .kid { color: #1a73e8; }</style>' +
        '<div class="panel">P</div><div class="a b">C</div><div class="outer"><span class="inner">D</span></div><div class="par"><span class="kid">K</span></div>',
    );
    expect(output).toMatch(/\.snd-panel\s*\{/);
    expect(output).toMatch(/\.snd-a\.snd-b\s*\{/);
    expect(output).toMatch(/\.snd-outer \.snd-inner\s*\{/);
    expect(output).toMatch(/\.snd-par\s*>\s*\.snd-kid\s*\{/);
    expect(output).not.toMatch(/[^a-zA-Z0-9_-]\.panel\s*\{/);
  });

  it('maps body selectors unconditionally to the inner replacement element', () => {
    const output = sanitizeEmailHtml(
      '<style>body > .label { color: #1a73e8; } body.newsletter .headline { color: #1a73e8; } html { color: #222222; }</style>' +
        '<body class="newsletter"><span class="label">L</span><span class="headline">H</span></body>',
    );
    // `body` means .email-body in every email — never the scope wrapper,
    // never conditioned on body-class presence.
    expect(output).toMatch(/\.email-canvas \.email-scope-\d+ \.email-body > \.snd-label\s*\{/);
    expect(output).toMatch(/\.email-canvas \.email-scope-\d+ \.email-body\.snd-newsletter \.snd-headline\s*\{/);
    // Bare `html` still maps to the scope wrapper, as before.
    expect(output).toMatch(/\.email-canvas \.email-scope-\d+\s*\{\s*color: #222222/);
    // The replacement element carries the bare class plus namespaced body classes.
    expect(output).toContain('class="email-body snd-newsletter"');
  });

  it('emits the inner replacement element even without body classes', () => {
    const output = sanitizeEmailHtml('<style>p { color: #1a73e8; }</style><p>Fixture</p>');
    expect(output).toContain('class="email-body"');
  });

  it('leaves sanitizer-added classes unprefixed', () => {
    const output = sanitizeEmailHtml(
      '<a href="https://example.com">Link</a><img src="https://example.com/i.png" alt="I" /><table><tr><td>C</td></tr></table>',
    );
    expect(output).toContain('email-body-link');
    expect(output).toContain('email-body-image');
    expect(output).toContain('email-body-table');
    expect(output).toContain('email-table-container');
    expect(output).not.toContain('snd-email-body-link');
    expect(output).not.toContain('snd-email-body-image');
    expect(output).not.toContain('snd-email-body-table');
    expect(output).not.toContain('snd-email-table-container');
  });

  it('keeps a sender border width attribute instead of forcing it', () => {
    const output = sanitizeEmailHtml('<table border="5"><tr><td>Fixture</td></tr></table>');
    expect(output).toContain('border="5"');
  });

  it('ignores unsafe body presentation values', () => {
    const output = sanitizeEmailHtml(
      '<html><head></head><body bgcolor="javascript:alert(1)" background="https://tracker.example/pixel.png"><p>Fixture</p></body></html>',
    );
    expect(output).not.toContain('javascript:');
    expect(output).not.toContain('tracker.example');
    expect(output).toContain('<p>Fixture</p>');
  });

  it.each([
    ['inherit', 'color'],
    ['inherit', 'background'],
    ['inherit', 'background-color'],
    ['initial', 'color'],
    ['initial', 'background'],
    ['initial', 'background-color'],
    ['unset', 'color'],
    ['unset', 'background'],
    ['unset', 'background-color'],
    ['revert', 'color'],
    ['revert', 'background'],
    ['revert', 'background-color'],
  ])('keeps CSS-wide keyword %s on %s, with and without !important', (keyword, prop) => {
    // No keyword special-cases in the filter: isolation comes from selector
    // scoping and class namespacing, never from rewriting sender values.
    expect(sanitizeCssStyle(`${prop}: ${keyword}`)).toBe(`${prop}: ${keyword}`);
    expect(sanitizeCssStyle(`${prop}: ${keyword} !important`)).toBe(`${prop}: ${keyword} !important`);
  });

  it('correctly calculates contrast ratio and parses colors', () => {
    const black = parseColorToRgb('#000000');
    const white = parseColorToRgb('#ffffff');
    expect(black).toEqual([0, 0, 0]);
    expect(white).toEqual([255, 255, 255]);
    if (black && white) {
      const ratio = getContrastRatio(black, white);
      expect(ratio).toBeGreaterThan(20);
    }
  });
});

describe('formatPlainTextEmail', () => {
  it('escapes HTML characters and auto-links URLs safely', () => {
    const text = 'Hello <friends> & everyone!\n\nCheck out https://missent.app for details.';
    const output = formatPlainTextEmail(text);
    expect(output).not.toContain('<friends>');
    expect(output).toContain('&lt;friends&gt;');
    expect(output).toContain('&amp;');
    expect(output).toContain('<a href="https://missent.app" target="_blank" rel="noreferrer noopener"');
    expect(output).toContain('https://missent.app</a>');
  });
});

 it('validates legacy background URLs like image sources', () => {
   const unsafe = sanitizeEmailHtml('<table background="javascript:alert(1)"><tr><td background="vbscript:bad">text</td></tr></table>');
   expect(unsafe).not.toContain('background=');
   expect(sanitizeEmailHtml('<table background="https://example.com/bg.png"></table>')).toContain('background="https://example.com/bg.png"');
 });
