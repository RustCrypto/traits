# RustCrypto Agent Instructions

Before investigating, reporting, or changing this repo, first retrieve, read,
and follow the latest project-wide RustCrypto Agent Instructions:

https://raw.githubusercontent.com/RustCrypto/meta/master/AGENTS.md

The full policy applies to this repo and takes precedence over the summary
below. If you cannot retrieve it, tell the user and do not submit issues, PRs,
or private security disclosures until you have read it.

Key points (not a substitute for the full policy):

- Before submitting, check all open issues and PRs, relevant history and
  advisories, and code TODOs. Avoid duplicate and speculative reports.
- Reserve private disclosures for credible security threats, including
  unexpected secret-dependent behavior where constant-time behavior is expected.
  Substantiate constant-time findings, preferably with `cargo checkct` where available.
- Zeroization issues belong in public, policy-compatible PRs or discussions,
  never private disclosures. Do not add blanket wipes of stack temporaries.
- Follow existing project conventions and keep changes focused. Do not introduce
  new tools or dependencies without prior maintainer agreement.
- Except for significant security findings, avoid bulk submissions and wait for
  maintainer engagement before opening more issues or PRs.

Note to human readers: we've added this because we're being inundated with
duplicate reports, reports for known issues / non-issues,  or otherwise
unhelpful reports which are making extra work for us as maintainers. The goal of
this policy is ultimately to cut down on the volume of such reports. While some
LLM-generated reports have been useful and helpful, the vast majority of them
are not and we'd like to prevent those from happening in the first place.
