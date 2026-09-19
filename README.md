# sanitize-email-html

a zero-dependency html sanitizer for rendering email safely. give it raw sender html, get back clean html you can drop into the dom without worrying about xss.

runs in the browser (or any dom environment). it uses DOMParser under the hood, so this is not a node thing.

## what it does

- strips scripts, forms, iframes, and anything executable
- strips event handlers and javascript: urls
- neutralizes dangerous css: url(), @import, css expressions, behaviors, positioning escapes, z-index tricks
- scopes surviving sender styles under a generated class, so sender css can't leak into your page
- constrains images and tables so they can't blow out your layout
- keeps what senders actually meant: layout tables, colors, fonts, alignment, spacing
- forces external links to open in a new tab with rel="noreferrer noopener"
- also ships formatPlainTextEmail, which turns plain text bodies into readable html

## where it came from

extracted from missent, a private email app i'm building. this is the exact sanitizer it uses, tests included.

## use

it's one file with zero dependencies. copy sanitizeHtml.ts into your project:

```ts
import { sanitizeEmailHtml } from './sanitizeHtml';

const clean = sanitizeEmailHtml(rawSenderHtml);
reader.innerHTML = clean;
```

drop the output inside an element with the email-canvas class for the intended containment styling. the companion rules live in src/email-canvas.css.

## test

```sh
npm install
npm test
```

53 tests, covering tag stripping, attribute scrubbing, css sanitizing, stylesheet scoping, and layout containment.

## license

mit, see [LICENSE](./LICENSE).
