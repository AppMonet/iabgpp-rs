# Decode benchmark comparison

- Date: 2026-02-17
- Command: `cargo bench -p iab_gpp --bench decode`
- Baseline log: `benchmarks/decode_baseline.txt`
- Optimized log: `benchmarks/decode_optimized.txt`

| Benchmark | Baseline (ns) | Optimized (ns) | Delta |
|---|---:|---:|---:|
| `gpp_parse` | 162.38 | 113.02 | -30.40% |
| `tcf_eu_v2_decode` | 366.98 | 283.06 | -22.87% |
| `gpp_decode_all_sections` | 783.12 | 585.54 | -25.23% |

Notes:
- Values above use the midpoint estimate from Criterion output (`time: [low mid high]`).
- Parser throughput improved materially for parse and decode-all workloads.
