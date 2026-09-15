import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { sanitizeCssStyle, sanitizeEmailHtml } from './sanitizeHtml';

const fixture = readFileSync('src/test/fixtures/marketing-email.html', 'utf8');
const styles = readFileSync('src/email-canvas.css', 'utf8');

describe('fictional responsive marketing stylesheet', () => {
  it('preserves scoped responsive rules while dropping malicious declarations and imports', () => {
    const html = sanitizeEmailHtml(fixture);
    const host = document.createElement('div');
    host.innerHTML = html;
    const css = host.querySelector('style')!.textContent!;
    expect(css).not.toMatch(/attacker|@import|url\(|position/);
    expect(css).toContain('color: #222222');
    expect(css).toContain('@media only screen and (max-width: 600px)');
    expect(css).toContain('display: none !important');
    expect(css).toMatch(/\.email-canvas \.email-scope-\d+ td\.snd-column/);
    expect(host.querySelectorAll('h1')).toHaveLength(2); // Authentic content retained.
    const second = sanitizeEmailHtml(fixture);
    expect(second.match(/class="(email-scope-\d+)"/)![1]).not.toBe(html.match(/class="(email-scope-\d+)"/)![1]);
  });

  for (const width of [390, 860]) it(`shows one variant and preserves column rules at ${width}px`, () => {
    const canvas = document.createElement('div');
    canvas.className = 'email-canvas';
    canvas.innerHTML = sanitizeEmailHtml(fixture);
    const outside = document.createElement('div');
    outside.className = 'mobile';
    document.body.append(outside, canvas);
    const sheet = canvas.querySelector('style')!.sheet!;
    // jsdom has no media-query/layout engine. Select matching CSSOM rules for
    // these explicit fixture widths, then let its style engine apply selectors.
    const active = document.createElement('style');
    active.textContent = Array.from(sheet.cssRules).map(rule => {
      if (rule.type !== 4) return rule.cssText;
      return width <= 600 ? Array.from((rule as CSSMediaRule).cssRules).map(r => r.cssText).join('\n') : '';
    }).join('\n');
    canvas.querySelector('style')!.remove();
    document.head.append(active);
    try {
      // jsdom's cascade does not implement stylesheet !important over inline;
      // validate the inline override contract separately, then remove it here.
      expect(active.textContent).toContain('display: none !important');
      canvas.querySelector('.snd-mobile')!.removeAttribute('style');
      const variants = ['.snd-desktop', '.snd-mobile'].map(selector => getComputedStyle(canvas.querySelector(selector)!).display);
      expect(variants.filter(display => display !== 'none')).toHaveLength(1);
      expect(variants[width <= 600 ? 0 : 1]).toBe('none');
      expect(getComputedStyle(outside).display).toBe('block');
      if (width <= 600) {
        expect(getComputedStyle(canvas.querySelector('td')!).display).toBe('block');
        expect(getComputedStyle(canvas.querySelector('td')!).width).toBe('100%');
      }
    } finally { active.remove(); canvas.remove(); outside.remove(); }
  });

  it('constrains the canvas and images/tables without forcing visible display', () => {
    expect(styles).toContain('contain: inline-size paint');
    expect(styles).toMatch(/\.email-canvas :where\(img, table\)\s*\{[^}]*max-width: 100% !important;[^}]*min-width: 0 !important;/);
    expect(styles).not.toMatch(/display:\s*(?:block|inline-block|table)\s*!important/);
  });
});

describe('CSS security boundary', () => {
  it.each([
    'background: u\\72l(https://attacker.invalid)',
    'background: image-set("https://attacker.invalid")',
    'width: expression(alert(1))',
    'color: var(--chrome)',
    'font: attr(data-secret)',
    'position: fixed',
    'background: u/**/rl(https://attacker.invalid)',
    'color: red !important } body { display: none',
    '-moz-binding: url(https://attacker.invalid)',
  ])('drops unsafe declaration %s without losing benign siblings', declaration => {
    expect(sanitizeCssStyle(`${declaration}; padding: 12px`)).toBe('padding: 12px');
  });

  it('rejects escape selectors, global at-rules, nesting and style attributes', () => {
    const output = sanitizeEmailHtml(`<style onload="alert(1)">
      @font-face { font-family: stolen; src: url(https://attacker.invalid); }
      @supports (display: block) { body { display: none; } }
      .a:has(+ div), [class] { color: red; }
      .a { & + div { display: none; } }
      .safe, p { color: blue; }
    </style><p>Fixture</p>`);
    expect(output).not.toMatch(/onload|alert|@font|@supports|attacker|:has|\[class\]|&amp;/);
    expect(output).toMatch(/\.email-canvas \.email-scope-\d+ \.snd-safe, \.email-canvas \.email-scope-\d+ p/);
  });
});
