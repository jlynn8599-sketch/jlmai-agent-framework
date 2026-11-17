# Verification before action: answering Governor Barr's four guardrails

On November 16, 2026, Federal Reserve Governor Michael S. Barr told the Seventh Annual ACM International Conference on AI in Finance in Milan that AI agents could "instantaneously detect yield differentials or stability signals and autonomously move funds at high speed, potentially accelerating runs that unfold in minutes, overwhelming traditional liquidity management and regulatory intervention timelines."

He also reported that major banks are already finding AI agents attempting to take actions in retail customer accounts, without the bank being able to verify authenticity, consent, or whether the action matches the customer's instructions.

Barr named four things financial institutions need: strict authentication; explicit consent verification for specific actions; technical controls limiting agent capabilities; and rules- and values-based constraints.

We built a prototype that enforces all four — before the action, not after it.

## 1. Strict authentication

Every policy in SENTINEL, our authorization and trust framework, is signed with Ed25519. No unsigned policy executes. No unsigned work order runs.

## 2. Explicit consent verification for specific actions

Our Intent Rules v1.0.0 define 17 intents across four tiers. Every action requires a signed, versioned work order naming the exact intent. A PreExecutionGate checks the work order before anything executes. No match, no execution — deny by default.

## 3. Technical controls limiting agent capabilities

Roles carry bounded authority. An observer can only observe (tier 1). Execution and treasury actions require higher tiers. Founder-level actions require the founder role. The agent cannot reach beyond the tier its work order grants.

## 4. Rules-based constraints, with a record

Every decision lands in an append-only audit log. In October 2026, our own security review found the dispatcher lacked role and tier authorization — a local operator could dispatch any tool without a tier check. We fixed it with PreExecutionGate, verified the fix, and recorded the audit: blocked probes, a decoy-vault self-test, a lockdown, sealed with a Merkle root.

SENTINEL is an engineering prototype under development — not a production deployment, not a certified product — with 29 passing tests at the current checkpoint. What it demonstrates is the mechanism Barr asked for: verification before action, with the proof attached to the action itself.

The Fed's own Financial Stability Report, released November 13, found 87% of surveyed market participants named AI a salient risk, up from 50% in the spring. The question Barr raised is no longer theoretical. Banks are already seeing agents act without verifiable consent. The answer is not to slow the agents down. It is to make every agent action prove itself first.

Governed AI agents. Verified action.

— JLM AI Agent LLC

- Intent Rules v1.0.0: https://github.com/jlynn8599-sketch/intent-rules-policy
- SENTINEL engineering update: https://github.com/jlynn8599-sketch/jlmai-agent-framework/blob/main/announcements/sentinel-engineering-progress-update.md
- Discussion #4247: https://github.com/NVIDIA/OpenShell/discussions/4247
