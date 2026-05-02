# Stress Test Findings

Date: 2026-04-30

Environment:
- VM target: `cgpt@192.168.122.54`
- Proxy bind: `127.0.0.1:53`
- Load tool: `dnsperf`

## Summary

The first stress pass shows that `secure-dns-proxy` can sustain six-figure QPS on localhost with mixed DoH/DoT/DoQ upstreams when logging is kept at `warn`, but it is sensitive to verbose logging, tight global backpressure, and sequential failover under upstream failure.

Race mode was substantially more resilient than sequential mode during partial upstream failure. The largest single performance regression came from reducing `max_in_flight` to `128`, which caused severe latency inflation and visible packet loss.

## Measured Scenarios

### 1. Race policy, hot cache, logging at warn

Config traits:
- `upstream_policy: race`
- `upstream_race_fanout: 3`
- cache enabled
- logging level `warn`

Results:
- Queries per second: `124620.429078`
- Queries completed: `1869819 / 1881592`
- Queries lost: `11773 (0.63%)`
- Average latency: `0.002235s`
- Max latency: `0.196165s`

Interpretation:
- This is the best result from the first pass.
- Local cache hits plus reduced log I/O let the proxy maintain high throughput with low average latency.

### 2. Race policy, cache misses, logging at warn

Config traits:
- `upstream_policy: race`
- `upstream_race_fanout: 3`
- cache-miss workload using randomized NXDOMAIN names
- logging level `warn`

Results:
- Queries per second: `102400.768291`
- Queries completed: `1536710 / 1548452`
- Queries lost: `11742 (0.76%)`
- Average latency: `0.003775s`
- Max latency: `0.668938s`

Interpretation:
- Throughput remained above `100k QPS` even when the workload forced real upstream activity.
- RSS increased materially during this run, suggesting the miss-heavy path should get a longer soak test for memory growth and object churn.

### 3. Low global in-flight limit, cache disabled

Config traits:
- cache disabled
- `max_in_flight: 128`
- shorter timeouts

Results:
- Queries per second: `3280.913784`
- Queries completed: `53581 / 57093`
- Queries lost: `3512 (6.15%)`
- Average latency: `0.857338s`
- Max latency: `1.623776s`

Interpretation:
- Tight global backpressure causes severe throughput collapse.
- The proxy does shed work, but the user-visible result is long latency and significantly higher loss.
- This is a clear tuning hazard for bursty workloads.

### 4. Sequential policy with DoH failure injected

Fault injection:
- outbound `tcp dport 443` dropped with `nft`
- this forced the first DoH upstream to fail so the proxy had to fall back

Config traits:
- `upstream_policy: sequential`
- cache disabled
- logging level `warn`

Results:
- Queries per second: `11370.039907`
- Queries completed: `174189 / 176459`
- Queries lost: `2270 (1.29%)`
- Average latency: `0.289234s`
- Max latency: `2.661245s`

Interpretation:
- Sequential fallback degrades sharply when the first upstream is unavailable.
- Throughput dropped by an order of magnitude versus the healthy race-policy miss workload.
- This is the clearest resilience gap from the first round.

### 5. Race policy with DoT and DoQ removed

Fault injection:
- outbound `tcp dport 853` dropped
- outbound `udp dport 784` dropped
- only DoH remained usable

Config traits:
- `upstream_policy: race`
- cache disabled for miss workload
- logging level `warn`

Results:
- Queries per second: `112668.753616`
- Queries completed: `1690162 / 1701925`
- Queries lost: `11763 (0.69%)`
- Average latency: `0.003794s`
- Max latency: `1.183549s`

Interpretation:
- Race mode absorbed the loss of DoT and DoQ surprisingly well.
- Performance stayed close to the healthy miss-heavy race run, indicating the fanout path hides partial upstream failure effectively in this setup.

## Additional Observations

### Logging overhead is significant

An earlier hot-cache run with `logging=info` produced:
- Queries per second: `89063.012272`
- Queries lost: `9048 (0.67%)`
- Average latency: `0.017160s`

Compared with the `warn` run:
- QPS improved from about `89k` to `125k`
- average latency improved from about `17ms` to `2.2ms`

Interpretation:
- Per-query or high-volume info logging is expensive enough to distort stress results.
- Future performance tests should keep logging at `warn` or below unless the goal is specifically to measure log-path cost.

### Socket churn deserves follow-up

During earlier inspection of the race-policy process, there were many open upstream TCP sessions and a visible number of `CLOSE-WAIT` sockets on port `853`.

Interpretation:
- This may be transient pool churn under load.
- It may also indicate cleanup lag or a reuse-path inefficiency worth deeper inspection during longer soak tests.

## Preliminary Conclusions

1. `race` is the strongest policy tested so far for both throughput and resilience.
2. Verbose logging materially reduces performance and should not be left enabled in serious load tests.
3. Global `max_in_flight` values that are too small can cripple throughput and produce long-tail latency.
4. Sequential fallback is much more exposed to first-upstream failure than the race path.
5. The miss-heavy path remained fast, but memory and socket behavior need longer-duration verification.

## Recommended Next Tests

1. Run multi-minute soak tests on the race-policy miss workload and sample RSS, file descriptors, and socket states over time.
2. Apply `tc netem` latency, jitter, and packet loss to upstream traffic only, then rerun race and sequential policies.
3. Sweep `max_in_flight` across a wider range to find a usable overload knee instead of the sharp collapse seen at `128`.
4. Compare race fanout values such as `1`, `2`, and `3` to measure upstream amplification versus latency hiding.
5. Investigate the observed `CLOSE-WAIT` population on DoT connections during heavy activity.
