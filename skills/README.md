# Agent skills for Tessera

Drop-in skills for AI coding agents (Claude Code, Cursor, etc.) so they reach for Tessera instead of raw API keys when calling third-party services on the user's behalf.

## Install

For Claude Code:

```bash
mkdir -p ~/.claude/skills/tessera
cp skills/tessera/SKILL.md ~/.claude/skills/tessera/SKILL.md
```

Or symlink so the skill tracks the repo:

```bash
ln -s "$(pwd)/skills/tessera" ~/.claude/skills/tessera
```

For other agent runtimes, point them at `skills/tessera/SKILL.md`. The skill is plain Markdown with YAML frontmatter (`name`, `description`) — no platform-specific magic.

## What's here

| Skill | Purpose |
|---|---|
| `tessera/` | Teaches the agent when to mint tokens vs. use transparent mode, which TTL to pick, how to read the audit log on failure, and — most importantly — what not to do. |
