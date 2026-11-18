# Public Security & Privacy Review

**Scope:** This portfolio and the two linked WQE7002 Assignment 1 repositories (Option A and Option B).  
**Review date:** 18 November 2026  
**Status:** Preliminary source review — not a complete security assessment.

## Confirmed practices

- The portfolio intentionally publishes a professional email address and links to GitHub and LinkedIn. It does not include a portrait, home address, telephone number, or employment history.
- The two linked coursework tools describe an **isolated, lecturer-authorised Docker lab** and require explicit scope validation before packet transmission.
- Both tools default to **dry-run** and require `--execute` to send packets.
- The documented scope restricts Option A to specified lab hosts and Option B to one lab target with an allow-list of ports. Both document a maximum rate of 20 probes/s and a maximum of two attempts per target or port.
- The portfolio's external links that open new tabs use `rel="noopener noreferrer"`.

## Findings and outstanding risks

| Finding | Assessment | Follow-up |
| --- | --- | --- |
| Student matriculation identifier appears in both linked repository names and coursework reports | **Privacy review needed**: public personal identifier, not a credential | Decide whether academic submission requirements justify publication. Consider private repositories or sanitised public copies; renaming files alone does not remove Git history. |
| Private Docker lab IP and MAC addresses appear in evidence files | **Context-dependent**: these are isolated lab addresses, not public routable targets | Confirm they are synthetic/approved for public disclosure and not identifying other people or real production infrastructure. |
| PCAP files are included in both linked repositories | **Not yet fully inspected** | Inspect packet payloads, metadata, hostnames, identifiers, and any captured credentials before asserting they are safe to publish. |
| GitHub file search returned no matches for sensitive-keyword queries | **Inconclusive** | Perform a full repository and Git-history secrets scan (e.g. Gitleaks), rather than interpreting zero search results as proof of safety. |
| Portfolio images and Google Fonts are served from third parties | **Privacy consideration** | Third-party hosts can receive visitors' IP addresses and request metadata. Consider self-hosting properly licensed image assets and system fonts; verify image availability and attribution/licensing. |
| No automated security scan has been run in this review | **Unverified** | Run static analysis and secret scanning on a local clone, and review dependencies and Git history. |

## Responsible disclosure and evidence handling

Only publish material that is authorised for public release. Before uploading screenshots, packet captures, JSON output, or network logs, review them for personal identifiers, authentication data, real infrastructure details, and third-party information. If sanitisation changes an evidence file, record the change and regenerate its SHA-256 checksum; retain an unmodified original only in a secure, access-controlled location where permitted.

## Verification status

This review is based on readable GitHub source files including the portfolio HTML/CSS/JavaScript, both project README files, reports, scope JSON, result JSON, Nmap XML and checksum manifests. **It is not a full audit**: raw PCAP packet contents, complete repository trees, Git history, GitHub configuration and actual running deployments have not been exhaustively tested.

## References

- [Portfolio](https://github.com/Wan-NotOne/cybersecurity-portfolio)
- [Option A](https://github.com/Wan-NotOne/WQE7002_Assignment_1_25057831_OptionA)
- [Option B](https://github.com/Wan-NotOne/WQE7002_Assignment_1_25057831_OptionB)
