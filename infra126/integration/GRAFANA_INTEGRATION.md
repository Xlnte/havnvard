# Grafana Integration

Import or merge `grafana/infra126_dashboard.json` into the existing diskaudit dashboard.

Panels:

1. verification age by host;
2. corruption suspects this month;
3. SLA attainment;
4. divergences by mutable score.

Set the PostgreSQL datasource variable and confirm the HavnVard UI URL in the corruption-suspect data link.

The age panel uses `last_verified_at`, not `hashed_at`. This prevents initial baselines from appearing as successful verification.
