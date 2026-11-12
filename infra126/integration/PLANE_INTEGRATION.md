# Plane Integration

Configure `INFRA126_PLANE_COMMAND` to an existing Plane ticket adapter.

Input is one JSON object on stdin. Required behavior:

- map `highest` to the highest supported Plane priority;
- include host, path, hashes, tier, mutable score, decision state, and run/divergence IDs;
- deduplicate using the supplied event data or let INFRA-126's persistent alert fingerprint suppress repeats;
- return zero only when the ticket was created or an existing matching ticket was confirmed.

The supplied command adapter does not assume Plane API credentials or schema.
