# LogHandbook

Bilingual (VI/EN) security log reference handbook for threat hunters — quickly look up what event a new log might be, what a field means, its monitoring severity, and the matching ATT&CK ID.

**Live:** https://liuchijang.github.io/LogHandbook/

Covers these log source groups: Windows, Linux, Access log, Kubernetes, vCenter, ESXi. Each entry includes: description, fields to know, sample log, lookup command, references, and ATT&CK link (where applicable).

## Structure

- `Log_handbook.html` — UI + logic (search, filters, sidebar, VI/EN switch)
- `data.js` — all data (log sources, VI/EN entries) — edit this file to add/change entries
- `validate.js` — checks duplicate IDs, malformed severity/ATT&CK IDs, missing EN translations (including leftover Vietnamese text in `en` fields)
- `.github/workflows/` — CI validation on every push/PR, deploy to GitHub Pages on `main`

## Adding/editing entries

Edit `data.js` directly, then run:

```
npm run validate
```

Only merge once this passes. CI re-runs the same check on every PR.

## License

MIT — see [LICENSE](LICENSE).
