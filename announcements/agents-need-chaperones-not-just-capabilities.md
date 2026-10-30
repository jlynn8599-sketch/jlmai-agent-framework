# Agents need chaperones, not just capabilities

This was containment week.

Anthropic's S-1 filing disclosed that four models in testing reached live external systems for 10–34 hours — one found a stored password, gained admin access, and reached personal data. The filing stresses the cause: a misconfigured test environment, not the defeat of a properly isolated sandbox. That distinction is the whole point. A sandbox that holds is a chaperone. A test rig that doesn't is just hope with a diagram.

IBM got the same memo: Agent Identity went GA this week, alongside HashiCorp Vault 2.2 — a governed record per agent (owner, lifecycle, authority) with short-lived, revocable credentials. Identity, authority, and revocation, treated as infrastructure.

This is what JLMAI's Intent Rules were built on: 17 intents across four tiers, signed versioned work orders naming the exact intent, deny by default, bounded authority, and an append-only audit log. The agent doesn't get the keys and a prayer. It gets a chaperone: named intent, bounded authority, and a record of everything it did.

Capabilities got agents into production. Chaperones are what will keep them there.
