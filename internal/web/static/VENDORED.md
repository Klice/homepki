# Vendored static assets

These files are third-party code committed into the repo so the binary stays
self-contained (`embed.FS` in `static.go` bundles them at build time). When
bumping versions, replace the file *and* update this doc.

| File | Version | Source URL | License |
| --- | --- | --- | --- |
| `pico.min.css` | 2.0.6 | https://cdn.jsdelivr.net/npm/@picocss/pico@2.0.6/css/pico.min.css | MIT |
| `htmx.min.js`  | 2.0.4 | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js                 | BSD-2-Clause |

`homepki.css` is our own — small overrides on top of pico for spacing, fonts,
status pills, and the app header/footer.

## Refresh script

```sh
cd internal/web/static
curl -sSLo pico.min.css "https://cdn.jsdelivr.net/npm/@picocss/pico@<VERSION>/css/pico.min.css"
curl -sSLo htmx.min.js  "https://unpkg.com/htmx.org@<VERSION>/dist/htmx.min.js"
```
