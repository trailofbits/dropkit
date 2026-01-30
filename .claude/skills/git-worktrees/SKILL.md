---
name: git-worktrees
description: Use git worktrees when running multiple Claude Code instances in parallel for different features - creates isolated workspaces with separate branches and virtual environments
---

# Parallel Development with Git Worktrees

## Overview

Git worktrees create isolated workspaces sharing the same repository, allowing work on multiple branches simultaneously without switching. This is essential when running multiple Claude Code instances in parallel.

**Core principle:** One worktree per Claude Code instance ensures isolation and prevents conflicts.

**Announce at start:** "I'm using the git-worktrees skill to set up an isolated workspace."

## When to Use

- Running multiple Claude Code instances for different features
- Need to work on a feature branch while keeping main branch accessible
- Parallel development on separate tasks

## Setup

```bash
# Create worktrees for parallel development
git worktree add ../dropkit-feature-a feature-a
git worktree add ../dropkit-feature-b feature-b

# Each worktree gets its own directory with full codebase
# Run Claude Code in each directory independently
```

## Guidelines for Parallel Instances

1. **One worktree per Claude Code instance** - Never run multiple instances in the same directory
2. **Separate branches** - Each worktree should be on its own feature branch
3. **Independent `uv sync`** - Run `uv sync` in each worktree (creates separate `.venv`)
4. **Tests run independently** - Each worktree can run its own test suite without conflicts
5. **Merge via main branch** - When features are complete, merge branches to main

## Managing Worktrees

```bash
# List all worktrees
git worktree list

# Remove a worktree when done
git worktree remove ../dropkit-feature-a

# Prune stale worktree entries
git worktree prune
```

## Potential Conflicts to Avoid

| Resource | Risk | Mitigation |
|----------|------|------------|
| `~/.config/dropkit/` | User config is shared | Don't modify during parallel dev |
| `~/.ssh/config` | SSH config is shared | Coordinate droplet names |
| DigitalOcean API | Creating droplets with same name | Use unique droplet names per worktree |

## Quick Reference

| Situation | Action |
|-----------|--------|
| Starting parallel work | Create new worktree with feature branch |
| New worktree created | Run `uv sync` to create isolated venv |
| Feature complete | Merge to main, remove worktree |
| Stale worktrees | Run `git worktree prune` |

## Example Workflow

```
You: I'm using the git-worktrees skill to set up an isolated workspace.

[Create worktree: git worktree add ../dropkit-auth feature/auth]
[Run uv sync]
[Run uv run pytest - all passing]

Worktree ready at ../dropkit-auth
Tests passing
Ready to implement auth feature
```
