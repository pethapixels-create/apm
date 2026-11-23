# Journey map data: current main (A/A)

- Commit: `3fa1b87cf0e088394ca9f531d18bbd71a6c9393c` (main) as both base and new.
- Harness: `danielmeppiel-perf-bench-macos` (Perf bench workflow, 3 hosted runners per run).
- Runners: linux = ubuntu-24.04, macos = macos-15. RTT modeled at 30 ms for every run.
- Pairs per runner: 2 (12 samples per cell = 3 runners x 2 pairs x 2 sides), except tree-200: 1 pair (6 samples).
- CPU = user+sys of apm and its children. "CPU p50" is pooled over all successful samples of both A/A sides; per-side p50 (base/new) in parentheses.
- Wall p50 is pooled over all successful samples and is given only for the fresh/network journeys (install-warm, install-cold, update), at the modeled 30 ms RTT. "n/a" = local journey.
- requests / round trips / connects / spawns are from the last successful sample (identical on every sample and on both sides in every cell).
- Samples column: successful samples / records with an error, out of total records.

| journey | fixture | OS | run ID | CPU p50 s (pooled; base/new) | wall p50 s @RTT | RTT ms | requests | round trips | connects | spawns | spawns by exe | samples ok / error records of total |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| install-warm | tree-10 | linux | 45089819612 | 3.374 (3.377/3.368) | 3.861 | 30 | 10 | 30 | 10 | 23 | git=23 | 12 / 0 of 12 |
| install-warm | tree-10 | macos | 45089862678 | 2.719 (2.597/2.730) | 3.736 | 30 | 10 | 30 | 10 | 23 | git=23 | 12 / 0 of 12 |
| install-warm | tree-50 | linux | 45090077292 | 11.687 (11.722/11.650) | 12.475 | 30 | 50 | 150 | 50 | 67 | git=67 | 12 / 0 of 12 |
| install-warm | tree-50 | macos | 45090240334 | 9.790 (9.754/11.095) | 13.292 | 30 | 50 | 150 | 50 | 67 | git=67 | 12 / 0 of 12 |
| install-warm | tree-200 | linux | 45090628693 | 53.543 (53.400/53.686) | 54.478 | 30 | 200 | 600 | 200 | 217 | git=217 | 6 / 0 of 6 |
| install-cold | tree-10 | linux | 45089819612 | 4.153 (4.153/4.162) | 5.562 | 30 | 40 | 80 | 20 | 123 | git=123 | 12 / 0 of 12 |
| install-cold | tree-10 | macos | 45089862678 | 4.261 (3.992/4.471) | 7.216 | 30 | 40 | 80 | 20 | 123 | git=123 | 12 / 0 of 12 |
| install-cold | tree-50 | linux | 45090077292 | 15.347 (15.275/15.492) | 17.083 | 30 | 200 | 400 | 100 | 567 | git=567 | 12 / 0 of 12 |
| install-cold | tree-50 | macos | 45090240334 | 16.603 (16.603/16.782) | 21.754 | 30 | 200 | 400 | 100 | 567 | git=567 | 12 / 0 of 12 |
| update | tree-10 | linux | 45091193304 | 1.760 (1.760/1.776) | 2.261 | 30 | 10 | 30 | 10 | 29 | git=29 | 12 / 0 of 12 |
| update | tree-10 | macos | 45091016047 | 1.632 (1.597/1.720) | 2.994 | 30 | 10 | 30 | 10 | 29 | git=29 | 12 / 0 of 12 |
| update | tree-50 | linux | 45091560100 | 5.022 (5.010/5.038) | 5.663 | 30 | 50 | 150 | 50 | 73 | git=73 | 12 / 0 of 12 |
| update | tree-50 | macos | 45091021927 | 6.061 (5.716/6.426) | 8.452 | 30 | 50 | 150 | 50 | 73 | git=73 | 12 / 0 of 12 |
| uninstall | tree-10 | linux | 45091193304 | 2.615 (2.604/2.615) | n/a | 30 | 0 | 0 | 0 | 12 | git=12 | 12 / 0 of 12 |
| uninstall | tree-10 | macos | 45091016047 | 2.094 (2.023/2.094) | n/a | 30 | 0 | 0 | 0 | 12 | git=12 | 12 / 0 of 12 |
| uninstall | tree-50 | linux | 45091560100 | 9.691 (9.724/9.686) | n/a | 30 | 0 | 0 | 0 | 12 | git=12 | 12 / 0 of 12 |
| uninstall | tree-50 | macos | 45091021927 | 10.088 (9.741/12.078) | n/a | 30 | 0 | 0 | 0 | 12 | git=12 | 12 / 0 of 12 |
| audit | tree-10 | linux | 45091193304 | 2.336 (2.345/2.327) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| audit | tree-10 | macos | 45091016047 | 1.798 (1.874/1.798) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| audit | tree-50 | linux | 45091560100 | 8.503 (8.556/8.503) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| audit | tree-50 | macos | 45091021927 | 8.330 (8.330/8.298) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| compile | tree-10 | linux | 45091193304 | 1.075 (1.066/1.075) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| compile | tree-10 | macos | 45091016047 | 0.868 (0.845/0.868) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| compile | tree-50 | linux | 45091560100 | 2.485 (2.485/2.497) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |
| compile | tree-50 | macos | 45091021927 | 2.497 (2.497/2.629) | n/a | 30 | 0 | 0 | 0 | 2 | git=2 | 12 / 0 of 12 |

## Failed journeys / fixtures

None. All 9 runs concluded success; all 25 cells have 0 error records.

## Run index

| run ID | journeys | fixture | OS | pairs |
|---|---|---|---|---|
| 45089819612 | install-warm, install-cold | tree-10 | linux | 2 |
| 45089862678 | install-warm, install-cold | tree-10 | macos | 2 |
| 45090077292 | install-warm, install-cold | tree-50 | linux | 2 |
| 45090240334 | install-warm, install-cold | tree-50 | macos | 2 |
| 45090628693 | install-warm | tree-200 | linux | 1 |
| 45091193304 | update, uninstall, audit, compile | tree-10 | linux | 2 |
| 45091016047 | update, uninstall, audit, compile | tree-10 | macos | 2 |
| 45091560100 | update, uninstall, audit, compile | tree-50 | linux | 2 |
| 45091021927 | update, uninstall, audit, compile | tree-50 | macos | 2 |

Run URLs: https://github.com/microsoft/apm/actions/runs/<run ID>

## Method note (request path)

`bench_ci.sh request` pushes from this environment were held at `action_required` with 0 jobs
(runs 45089665298, 45089677586, 45089728273, 45089735578, 45089759711). Commit signing here
requires the `Co-authored-by: copilot-swe-agent[bot]` trailer, and agent-credited pushes require
workflow approval. Those branches were deleted. All data above comes from `workflow_dispatch`
of perf-bench.yml on ref `danielmeppiel-perf-bench-macos` with the same inputs (base, new,
fixtures, journeys, rtt=30, pairs, os), so no commit or approval was needed.
