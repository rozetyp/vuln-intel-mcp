# bug-bounty-hunting skill + MCP playbook

Two **MIT-licensed** companion docs for driving the [vuln-intel](https://mcp.rozetyp.com/signup) MCP
on a real bug-bounty hunt. Both are self-contained: load either one and it drives the MCP with nothing
else to install.

- **[SKILL.md](SKILL.md)** is a self-contained Claude skill: expert adversarial cognition (attack the
  assumption, hit the seam, transfer a proven mechanism, drill to the mechanism) plus the honesty
  discipline that keeps a clever idea from becoming a fabricated report (acceptance != impact, the
  validity gate, prove the mechanism out-of-band), the hunt loop, and the tool interface. Drop the
  `bug-bounty-hunting/` folder into your agent's skills directory (e.g. `~/.claude/skills/`) and it loads
  on triggers like "hunt for bugs" or "is this exploitable".
- **[MCP_PLAYBOOK.md](MCP_PLAYBOOK.md)** is the deeper, on-demand operating manual for the MCP: the
  per-tool gotchas, the `find_attack_approaches` ideation loop, the `find_continuations` position layer,
  the recon plumbing, and the verification patterns that kill a false positive.

The skill is the cognition and discipline layer you keep loaded; the playbook is the deep reference you
consult on demand. They overlap by design so each stands alone.

## Use with the MCP

Get a free key: **https://mcp.rozetyp.com/signup** (enter your email, your personal key is sent over).
Then point your agent's MCP client at `mcp.rozetyp.com` and load the skill.

## License

MIT, see [LICENSE](LICENSE).
