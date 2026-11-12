# HELM WaitingRoom Integration

Every verification run requests P3 admission before enqueuing or hashing work.

Acquire input:

```json
{"run_id":"UUID","host":"nas-1","tier":"A","priority":"P3"}
```

Release receives the same shape.

The acquire command must either:

- block until P3 admission is granted and return zero; or
- return nonzero, causing the run to enter `blocked` and fail loudly.

GPU percentage is not used as a substitute for WaitingRoom policy. Hashing is CPU/I/O work, but it can still contend with storage, CPU, and system scheduling.
