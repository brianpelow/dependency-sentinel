# 0002. Security findings come only from OSV, never from the LLM

**Status:** Accepted

## Context

The tool uses a language model to write migration narratives. It would be easy, and tempting, to also let the model assess severity or summarize "how bad is this really" in a way that feeds the risk level. That would be a serious mistake.

A language model can hallucinate a vulnerability that does not exist, and -- more dangerously -- it can fail to mention one that does. Either error in a security tool is unacceptable: a false vulnerability erodes trust until people ignore the tool, and a missed vulnerability is the exact failure the tool exists to prevent.

## Decision

Advisories are produced only from OSV.dev data, deterministically. The risk engine consumes those advisories through fixed rules. The LLM is handed the finished assessment and writes prose about it. It never sees a path to create, remove, or reweight an advisory or a risk level.

When OSV cannot be reached, the tool records a security-data gap for that dependency rather than reporting "no advisories." An absent answer is marked unknown, never assumed clean.

## Consequences

**Gained:** The security verdict is reproducible and auditable. Read the OSV response, read the rule, and you can verify the finding. The narrative adds readability without becoming a channel for hallucinated or suppressed security claims.

**Accepted:** The tool only knows about vulnerabilities OSV knows about. That is a real limit, but it is a limit of a trustworthy data source, not of a model's memory -- and it is the correct place to draw the boundary.
