# Domain docs

## Layout and reading rules

This repo uses a single-context layout:

- `GLOSSARY.md` at the repo root contains domain terminology.
- `docs/adr/` contains architecture decision records.

Before exploring the codebase, read the glossary and ADRs relevant
to the area being changed.

If these files are absent, proceed silently. Domain modeling creates
them when terms or decisions are resolved.

## Use the glossary's vocabulary

Use defined terms in issue titles, proposals, hypotheses, and test names.
If a needed concept is missing, reconsider the term or note the gap
for domain modeling.

## Flag ADR conflicts

When a proposal contradicts an existing ADR, identify the ADR and
explain why the decision should be reopened.
