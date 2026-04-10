# TODOS — unovault

Living list of deferred work and follow-ups. Each entry has: what, why, pros, cons, context, dependencies.

---

## Design / Mockups

### TODO: Generate real visual mockups with gstack designer

**What:** Once the OpenAI API key is set up locally (`$D setup` or save to `~/.gstack/openai.json`), run `$D variants` for the three anchor screens: Locked Vault Home, Vault List, Item Detail. Then `$D compare --serve` to pick the direction.

**Why:** The /plan-design-review session produced a complete text spec and ASCII wireframes, but no rendered mockups. The Week 1 Design Spike Gate will benefit enormously from having 3 visual directions to react to, rather than building from imagination.

**Pros:**
- Gives the week 1 spike a visual starting point instead of "from scratch"
- Surfaces taste decisions that text specs hide
- Lets you invite a designer friend to weigh in on real visuals, not words
- The mockups become the approved reference for the whole design system work in weeks 10-13

**Cons:**
- Requires OpenAI API credits (a few dollars per session typically)
- Generated mockups can still look AI-ish if the brief is vague; the text spec already contains the strong brief

**Context:**
The design spec in `~/.gstack/projects/jamest-musinsa-unovault/james-main-design-20260410-190548.md` ("Design Spec v0" section) has the full brief material. Specifically:
- Typography: Inter Display + Iowan Old Style (ceremonial)
- Color: warm neutrals (#FBFAF7 bg) + terracotta accent (#B8532C)
- Layout: command bar + single panel (Raycast/Linear inspired)
- Locked Home: single centered card with Touch ID primary + password secondary
- Vault List: 60px rows, sync status bar at bottom
- Item Detail: sheet slide-up, not master-detail split

Sample command once key is set up:
```bash
D=~/.claude/skills/gstack/design/dist/design
DESIGN_DIR=~/.gstack/projects/jamest-musinsa-unovault/designs/locked-vault-home-<date>
mkdir -p "$DESIGN_DIR"
$D variants --brief "<brief from design doc Design Spec v0 section>" --count 3 --output-dir "$DESIGN_DIR/"
$D compare --images "$DESIGN_DIR/variant-A.png,$DESIGN_DIR/variant-B.png,$DESIGN_DIR/variant-C.png" --output "$DESIGN_DIR/design-board.html" --serve
```

**Depends on:** OpenAI API key set up via `$D setup` (one-time).

**Blocked by:** Nothing else.

**Priority:** High — best done before week 1 spike starts (ideally before any Rust code).
