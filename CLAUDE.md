# Rules for this repository

This repository is public twice over: the source is a public GitHub repository,
and every file in it is served on the open web by GitHub Pages. Treat every
byte committed here as published to the world, permanently. Deleting a file
later does not remove it from git history.

## Never publish credentials or personal identifiers

These must never appear in any file, file name, commit message, or commit
identity in this repository:

- Usernames, passwords, passphrases, PINs.
- API keys, tokens, client secrets, session cookies, private keys, certificates.
- Connection strings and URLs with embedded credentials.
- Email addresses, phone numbers, street addresses.
- Local file paths that contain a user name (Windows user folders, Unix home folders).
- Database files, `.env` files, exported mail, logs, raw data extracts.
- Anything from an employer or client.

A site that needs a secret to work cannot be hosted here. Keys placed in
browser-side code are readable by every visitor. Say so and stop; do not look
for a way to hide the key.

## Required before every commit

1. Run the scan from the repository root:

   ```
   python tools/check_secrets.py
   ```

2. It must print `OK` and exit 0. Exit 1 (findings) or exit 2 (scan could not
   run) both mean: do not commit, do not push.
3. Fix findings by removing the content. Never work around the scan:
   - no `git push --no-verify`,
   - no editing the scanner's rules to make a finding disappear,
   - no adding a line to `tools/secrets_allowlist.txt` without the owner's
     explicit approval of that exact string in the current conversation.
4. The scan matches known patterns only. Passing it is necessary, not
   sufficient: also read what you are about to publish.
5. Read `git status` before staging and stage files by name. Build caches and
   compiled files (`__pycache__`, `.pyc`, `node_modules`, source maps) embed
   local paths and string constants. They do not belong here.

## Required once per clone

```
git config core.hooksPath .githooks
git config user.name dismalnow
git config user.email dismalnow@users.noreply.github.com
```

The first line makes the scan run automatically before every push. The other
two keep a personal email address out of the public commit history; the scan
rejects any commit whose author or committer is not a GitHub no-reply address.

## Publishing a site

1. Copy only the built, static files into a new top-level folder named for the
   site. Never copy a whole project directory.
2. Use relative paths inside the site (`./style.css`, not `/style.css`).
3. Add a line for it to the list in the root `index.html`.
4. Run the scan, commit, push to `main`.

Do not edit `CNAME` or `.nojekyll`.
