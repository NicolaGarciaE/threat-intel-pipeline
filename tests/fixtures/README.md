# Test fixtures

Everything in this directory is **synthetic**: made up on purpose for the tests,
with the exact structure of each source's published files. None of it is real
KEV or EPSS data, and it must never be presented as such. CVE identifiers use the
year 2099 so they cannot be mistaken for real ones.

`raw/`:

| File | What it is |
|---|---|
| `kev_valid.json` | KEV catalog with 3 records, each with the 12 fields of the real feed |
| `kev_bad_top_level.json` | Like `kev_valid.json`, with `catalogVersion` renamed to `version` |
| `kev_empty.json` | Empty file (0 bytes) |
| `epss_valid.csv` | EPSS scores with the `#` line and the header; the tests gzip it in memory |
| `epss_bad_header.csv` | Header `cve,epss,percentil` instead of `cve,epss,percentile` |
| `epss_old_score_date.csv` | `score_date` of 2026-10-20, too old for the snapshot dates used in the tests |
| `epss_empty.csv.gz` | Empty file (0 bytes) |

Larger inputs (to reach the minimum-row thresholds) and other variants are
generated in memory by `tests/helpers.py` and the tests themselves.
