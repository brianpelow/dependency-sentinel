# 0001. The engine is transport-agnostic

**Status:** Accepted

## Context

The requirement was an agent that "runs as an async event in the enterprise." The easy version bakes the trigger into the tool: a script with a cron line, or a Lambda handler with the logic inside it. That couples the triage logic to one execution model and makes it untestable without simulating the trigger.

## Decision

The engine takes manifests in and returns a report plus a delta. It knows nothing about GitHub Actions, cron, daemons, or queues. Two thin scheduler shells drive it: a GitHub Actions workflow and an APScheduler daemon. Both gather manifests, call the same engine, and deliver the same output.

## Consequences

**Gained:** The triage logic is tested in isolation with mocked I/O, no scheduler involved. New execution models (a webhook, a queue consumer, a different CI) are new shells, not forks of the logic. The same binary runs in CI and as a service.

**Accepted:** There is a little duplication between the CLI and the daemon in how they assemble config. That is a small price for keeping the core free of any transport knowledge.
