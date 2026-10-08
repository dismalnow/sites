# sites

Static sites shared for feedback. Served by GitHub Pages at https://sites.dismal.me.

## Layout

Each site is one top-level folder with its own `index.html`:

```
index.html        landing page listing the published sites
CNAME             custom domain for GitHub Pages (do not edit)
.nojekyll         serve files as-is, no Jekyll build
CLAUDE.md         publishing rules, read by AI assistants working here
tools/            credential scan and its tests
.githooks/        pre-push hook that runs the scan
<site-name>/      one folder per site -> https://sites.dismal.me/<site-name>/
```

## Publishing a site

1. Add a folder named for the site, containing `index.html` and its assets.
2. Use relative paths inside the site (`./style.css`, not `/style.css`).
3. Add a line for it to the list in the root `index.html`.
4. Run `python tools/check_secrets.py`. It must print `OK`.
5. Commit and push to `main`. It is live in about a minute.

## Rules

- Everything here is public: the pages and this repository's source.
- Static files only. No server-side code, no secrets, no personal data.
- Full rules are in `CLAUDE.md`.

## Credential scan

`tools/check_secrets.py` fails if any committable file, or any commit's author
email, looks like a credential or personal identifier. Enable the automatic
pre-push run once per clone:

```
git config core.hooksPath .githooks
```

Run its tests with:

```
python -m unittest discover -s tools -p "test_*.py"
```
