# PRESI Integration

Use `havnvard_bitrot.reporting.verification_report(repository)` as a section in the existing daily report.

The report deliberately distinguishes:

- baseline-only files;
- successful re-verification within 7/30/90 days;
- current SLA attainment;
- open corruption suspects;
- monthly divergence count.

For immediate events, configure `INFRA126_TG_COMMAND` to the existing TG PRESI adapter. The command receives one JSON object on stdin:

```json
{"event_type":"possible_corruption","severity":"warning","payload":{}}
```

It must return nonzero if delivery fails. Do not wrap it in a shell command that always exits zero.
