## What this changes

<!-- One or two sentences. What does this do, and why? -->

Closes #

## Type

- [ ] New detection rule (rule ID agreed on an issue first)
- [ ] False-positive fix
- [ ] Bug fix
- [ ] Documentation
- [ ] Other:

## Checklist

- [ ] `pytest -q` passes locally
- [ ] Added tests covering **both** a true positive and a negative case that must not fire
- [ ] New/changed rule documents the attack it detects, not just the pattern it matches
- [ ] Finding text tells the reader concretely what to change
- [ ] Commits are signed off (`git commit -s`) per the DCO
- [ ] No AI-assistant attribution in commit messages or this description
- [ ] No secrets, credentials, internal hostnames, or personal paths in the diff

## For new rules only

**Rule ID:**
**Family:** <!-- Docker / GHA / MCP / PI / Terraform / … -->
**Severity + why:**

**Why existing tools miss this:**

**Safe idioms deliberately excluded** (patterns that superficially match but must not fire):

## Verification

<!-- Paste the before/after Vigil output, or the failing test that now passes. -->

```
```
