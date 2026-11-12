# migrations/ — change history, not an install path

These files are the schema's change history on the original HavnVard deployment, applied one at a time as the
system grew. Several name that deployment's hosts or read a table from another of its systems, so run in order on an
empty database they do **not** build the schema.

* **New install:** use `schema/baseline.sql` (see the README, "Database").
* **Existing deployment upgrading:** apply the new dated files here in order, as before.
* **Maintainers:** after adding a migration and applying it to a working database, regenerate the baseline:

```bash
pg_dump "$POSTGRES_URL" --schema-only --no-owner --no-privileges -n diskaudit -f /tmp/diskaudit.sql
python3 scripts/make_baseline_schema.py /tmp/diskaudit.sql > schema/baseline.sql
```
