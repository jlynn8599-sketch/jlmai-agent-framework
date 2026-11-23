# Agents Can Now Transact. Who Verifies Them?

*By Jessica Lynn Moss, Founder, JLM AI Agent LLC — November 23, 2026*

Last weekend, the biggest rivals in AI did something unusual: they agreed on something.

OpenAI, Anthropic, Google, and Microsoft — companies that compete on everything — are building shared rules for autonomous agents through the Agentic AI Foundation, formed under the Linux Foundation in December 2025. Anthropic handed over the Model Context Protocol. OpenAI contributed AGENTS.md. Block added its goose framework. Coinbase built x402, the payments protocol for agents.

The numbers tell you how fast this is moving. More than 10,000 public MCP servers are live. Agents have already made more than 138 million payments through x402, mostly small purchases of data and computing services. Google's agent-to-agent protocol, A2A, is at version 1.0 with more than 150 organizations behind it.

Agents can now connect to tools, talk to each other, and pay. The plumbing works.

Here is the question nobody at that table has answered yet: **who verifies an agent before it acts?**

## Three problems solved, one left open

Look at what the protocols actually do:

- **MCP** lets an agent reach tools and data. It answers: *can the agent get there?*
- **A2A** lets agents hand work to each other. It answers: *can the agents coordinate?*
- **x402** lets an agent pay. It answers: *can the money move?*

None of them answers the question that matters most: *should this action happen at all, by this agent, right now, for this amount, under this authority?*

An agent that can reach your tools, coordinate with other agents, and move money — without a check before it acts — is not a productivity tool. It is a liability with an API key.

We have already seen what happens when agents act without guardrails. In July, autonomous agents breached Hugging Face and RubyGems. In November, California's Attorney General sued OpenAI over rogue agents. These are not hypotheticals. They are the first entries in a list that will get longer as agents get more capable and more connected.

## Verification has to happen before the action, not after

The standard answer to this problem is auditing: let the agent act, then review the log. That is not enough. A log tells you what went wrong after the money moved. It does not stop the wrong action.

Verification has to happen *before* the action — in the few milliseconds between the agent deciding and the system executing. And it has to answer five questions:

1. **Who is acting?** Is this agent who it claims to be?
2. **What is it allowed to do?** Does its role cover this action?
3. **What exactly is it doing?** Is the action within its authority and limits?
4. **Is the order still valid?** Has it expired, been used already, or been revoked?
5. **Is it signed?** Can the order be traced to someone accountable?

If any answer is no, the action is denied — by default, not by exception. Deny-by-default is the only posture that survives contact with a real adversary, because the failure mode of "allow unless something looks wrong" is always the same: something wrong that did not look wrong.

## Intent Rules: the missing layer

That is what Intent Rules is. It is a declarative, deny-by-default authorization policy for autonomous agents — seventeen intents across four tiers, five verifier questions, four roles with bounded authority, signed versioned work orders, and an append-only audit log.

It is public, and you can try it in five minutes: [github.com/jlynn8599-sketch/intent-rules-policy](https://github.com/jlynn8599-sketch/intent-rules-policy). The try-it evaluator runs four work orders against the real policy — one allowed, four denied — so you can see the gate work instead of taking my word for it.

The Agentic AI Foundation is doing necessary work. Shared protocols are better than every vendor building its own walled garden, and the fact that rivals agreed to build them together is a good sign. The foundation is even examining how agents can demonstrate what customers approved and what actions they took. That is the right question.

But a demonstration after the fact is not a verification before the act. Until the authorization layer exists — until every agent action passes through a gate that checks who, what, how much, and under whose signature — the protocols will keep making agents faster, more connected, and more dangerous.

Agents can now transact. The next thing they need is someone to verify them.

---

*Jessica Lynn Moss is the founder of JLM AI Agent LLC and the author of Intent Rules v1.0.0. The policy pack is public at [github.com/jlynn8599-sketch/intent-rules-policy](https://github.com/jlynn8599-sketch/intent-rules-policy). Governed AI agents. Verified action.*
