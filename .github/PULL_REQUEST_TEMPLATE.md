## What this changes

<!-- One behaviour change. Link the issue it closes, if any. -->

## Why

<!-- The problem, not the diff. -->

## Safety impact

- [ ] Does not touch the SQL guard (`safety.py`) or the tool registration policy.
- [ ] Touches the guard: I added both an accepted case and a rejected case to `tests/test_safety.py`.
- [ ] Adds a new tool: I stated whether it is read-only and why it cannot be done with an existing one.
- [ ] Adds a new dependency: I explained why it is worth the supply-chain cost.

## How I verified it

```
python -m pytest tests -q      # 24 passed
```

<!-- For tool changes: the tool call you ran and the response you got, with secrets redacted. -->
