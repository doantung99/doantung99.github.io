---
title: "System Online — Welcome to LazyBlog"
date: "2026-06-26"
author: "XV5HP"
tags: [meta, getting-started]
draft: false
summary: "Your local LazyBlog instance is live. Here's how to write your first real post and make this blog your own."
icon: "📡"
---

If you're reading this, the transmitter is warm and the local stack is
running. This is a sample post — delete it whenever you like and start
broadcasting your own signal.

::: highlight
**This blog has no database and no build step.** Every post is a plain
markdown file under `content/posts/` named `YYYY-MM-DD-slug.md`. Drop a
file in, refresh, and it's live.
:::

## Two ways to write

1. **Edit files directly.** Create `content/posts/2026-06-27-my-post.md`
   with YAML frontmatter (title, date, tags...) and markdown below it.
2. **Use the admin UI** at `/admin`. It ships with an EasyMDE editor,
   live server-side preview, tag chips, and image upload. You'll need to
   set an admin password first (see below).

## Set up the admin login

To unlock `/admin`, generate a password hash and drop it into `.env`:

```bash
docker compose exec app php scripts/hash-password.php yourpassword
```

Copy the printed hash into `ADMIN_PASSWORD_HASH="..."` in your `.env`,
then reload the page. That's it.

## A few things that just work

- Standalone image lines render as full-bleed figures with a theme tint.
- A bare YouTube URL on its own line auto-embeds as a 16:9 player.
- Inline frequencies like `145.800 MHz` become freq-tag chips automatically.
- Every post is also served as raw markdown at `/posts/{slug}.md`, and the
  whole site publishes `llms.txt`, `llms-full.txt`, and a valid RSS feed.

| Theme | Vibe |
|-------|------|
| amber | warm phosphor (default) |
| green | classic terminal |
| C64   | lavender retro |
| LCD   | paper-sage |

Flip themes from the picker in the header — your choice persists in
localStorage.

73 de LazyBlog. Now go write something real.
