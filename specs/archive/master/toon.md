# TOON Investigation and PoC for SystemManager

This document summarizes an initial investigation and PoC for using a compact
TOON-like representation to reduce token cost when sending structured data
(e.g., `SystemStatus`) to LLMs.

Summary:
- TOON is a compact format designed to reduce token count for LLM inputs.
- For an immediate, low-dependency approach we implement a deterministic
  compact JSON serializer (short keys, tight separators) as a PoC in
  `src/utils/toon.py`.
- This PoC reduces token size by shortening keys and flattening structures.

What I added:
- `src/utils/toon.py`: a small converter with `system_status_to_toon()` and
  `toon_to_system_status()` plus a `model_to_toon()` dispatcher.
- `tests/test_toon.py` (unit test proving round-trip for `SystemStatus`).

Design notes & tradeoffs:
- This PoC uses short JSON keys (e.g., `c` for cpu, `m` for memory) with
  stable mappings. It's human-readable and easy to inspect.
- The full upstream `toon-format` project may implement a more compact
  binary/text encoding and richer schema features; switching to it is
  straightforward later.
- We kept serialization deterministic and reversible for safety (we can
  rehydrate data into Pydantic models).

Integration options:
- Add an optional `format` parameter to MCP tools, e.g. `get_system_status(format="toon")`.
- Keep default JSON behavior for backwards compat and add `format=="toon"` to return the compact string.
- On the LLM side, prompt templates should document the compact format mapping.

Next steps:
- Evaluate token savings on representative outputs (measure token counts with your LLM/evaluator).
- Consider adopting upstream `toon-format` if savings and interoperability are compelling.
- Add converters for other models (`ContainerInfo`, `DirectoryListing`, `NetworkStatus`).
