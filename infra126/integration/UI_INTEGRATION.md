# Web UI Integration

Register the blueprint in the existing HavnVard Flask application:

```python
from infra126_blueprint import bp as infra126_bp
app.register_blueprint(infra126_bp)
```

Routes:

- `GET /havnvard/verification-status`
- `GET /havnvard/verification-status?host=server-1&min_hash_age_days=30`
- `GET /havnvard/verification-file/<file_key>`
- `GET /havnvard/verification-divergences.csv`
- `GET /havnvard/verification-divergences.json`

The existing dedup, cleanup, and backup queries should join `diskaudit.v_infra126_verification_age` by `(host,path,inode)` or use its `file_key` and expose:

- `first_hashed_at`
- `current_baseline_at`
- `last_verified_at`
- `days_since_last_verification`
- `verification_count`
- `baseline_revision_count`
- `hash_divergence_count`
- `hash_status`
- `is_critical`

Do not display `hashed_at` as “verified.” It is the current baseline timestamp. Successful assurance age comes from `last_verified_at`.

The uploaded package did not contain the existing HavnVard UI source, so this archive includes a complete blueprint, templates, and query contract rather than fabricating edits to unseen files.
