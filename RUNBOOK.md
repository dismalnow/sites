# Publish to site: runbook

Paste the block below into any Claude chat that has a site ready to share.
It is written for a chat that knows nothing about this repository.

```
PUBLISH TO SITE

Goal: publish the static site from this chat to
https://sites.dismal.me/<site-name>/ and link it from the landing page.

Facts
- Host: GitHub Pages. Public repo dismalnow/sites, branch main, root folder.
  A push to main is live in about a minute.
- One top-level folder per site. The folder name is the URL path:
  lowercase, hyphens, no spaces.
- Everything pushed is public and permanent: the pages and the source.

Stop and tell me, do not work around it, if:
- The site needs a server, a database, a login, or a secret or API key to work.
  Static files only.
- You cannot get push access to dismalnow/sites in this chat. Give me the
  site as downloadable files instead, so I can publish from a chat that can.
- The credential scan fails or cannot run.
- A folder with that name already exists and I did not say "update".

Steps
1. If I gave no site name, ask for one. Show me the list of files you intend
   to publish and wait for my OK.
2. Attach the repo dismalnow/sites with push access and clone it.
3. Read CLAUDE.md in the repo and follow it. Where it disagrees with this
   runbook, CLAUDE.md wins.
4. Once per clone:
     git config core.hooksPath .githooks
     git config user.name dismalnow
     git config user.email dismalnow@users.noreply.github.com
5. Create <site-name>/ and copy in only the built static files: index.html
   and its assets. Relative paths only (./style.css). No project folders,
   no .env files, no data dumps, no caches.
6. In the root index.html, add one line to the list. On first use it replaces
   the "Nothing published yet." line:
     <li><a href="<site-name>/">Name<span>One-line description</span></a></li>
7. Run:  python tools/check_secrets.py
   It must print OK and exit 0.
8. Read git status, stage files by name, commit, push to main.
   Never use --no-verify.
9. Verify: load https://sites.dismal.me/<site-name>/ and
   https://sites.dismal.me/ and confirm both show the new site.
10. Report the URL, the files published, and the scan's OK line.
```

To update a site that is already published, say "update" and name the site.
The steps are the same, except step 5 replaces the files in the existing
folder and step 6 is skipped unless the description changed.
