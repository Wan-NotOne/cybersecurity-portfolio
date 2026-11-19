# Public Security & Privacy Review

**Scope:** This portfolio, the new curated public project folders, and a preliminary review of the original coursework sources.  
**Review date:** 19 November 2026  
**Status:** In progress — source and evidence-text review; not a complete security assessment.

## Confirmed practices

- The portfolio intentionally publishes a professional email address and links to GitHub and LinkedIn. It does not include a portrait, home address, telephone number, or employment history.
- The two linked coursework tools describe an **isolated, lecturer-authorised Docker lab** and require explicit scope validation before packet transmission.
- Both tools default to **dry-run** and require `--execute` to send packets.
- The documented scope restricts Option A to specified lab hosts and Option B to one lab target with an allow-list of ports. Both document a maximum rate of 20 probes/s and a maximum of two attempts per target or port.
- The portfolio's external links that open new tabs use `rel="noopener noreferrer"`.

## Findings and outstanding risks

| Finding | Assessment | Follow-up |
| --- | --- | --- |
| Student matriculation identifier appears in original coursework repository names and reports | **Privacy review needed**: public personal identifier, not a credential | Decide whether academic submission requirements justify publication. Consider private repositories or sanitised public copies; renaming files alone does not remove Git history. |
| Private Docker lab IP and MAC addresses appear in evidence files | **Context-dependent**: these are isolated lab addresses, not public routable targets | Confirm they are synthetic/approved for public disclosure and not identifying other people or real production infrastructure. |
| PCAP files are included in both linked repositories | **Packet structure reviewed; publication authorisation pending** | Original Option A and B captures were decoded and packet headers inspected on 19 November 2026. No application payload was present. Confirm authorisation, verify SHA-256, and retain the distinction between packet inspection and full security clearance. |
| GitHub file search returned no matches for sensitive-keyword queries | **Inconclusive** | Perform a full repository and Git-history secrets scan (e.g. Gitleaks), rather than interpreting zero search results as proof of safety. |
| Portfolio images and Google Fonts are served from third parties | **Privacy consideration** | Third-party hosts can receive visitors' IP addresses and request metadata. Consider self-hosting properly licensed image assets and system fonts; verify image availability and attribution/licensing. |
| No automated security scan has been run in this review | **Unverified** | Run static analysis and secret scanning on a local clone, and review dependencies and Git history. |

## Responsible disclosure and evidence handling

Only publish material that is authorised for public release. Before uploading screenshots, packet captures, JSON output, or network logs, review them for personal identifiers, authentication data, real infrastructure details, and third-party information. If sanitisation changes an evidence file, record the change and regenerate its SHA-256 checksum; retain an unmodified original only in a secure, access-controlled location where permitted.

## Verification status

This review is based on readable GitHub source files including the portfolio HTML/CSS/JavaScript, both project README files, reports, scope JSON, result JSON, Nmap XML and checksum manifests. **It is not a full audit**: raw PCAP frames have been structurally parsed, but checksums, complete repository trees, Git history, GitHub configuration and actual running deployments have not been exhaustively tested.

## References

- [Portfolio](https://github.com/Wan-NotOne/cybersecurity-portfolio)
- [Public ARP project](projects/network-device-discovery/)
- [Public TCP SYN project](projects/tcp-syn-port-scanner/)

## Curated portfolio edition (current state)

The two public-edition project folders are present on `main`, and the live site's project cards link to these folders. The public project folders currently contain README, requirements, source code and unit-test files, but no `evidence/` directories. This does **not** remove information from separately published original coursework repositories. The new source and unit tests still require a fresh test run, full-tree identifier review and Git-history secrets scan before publication is considered verified.

## Evidence review — 19 November 2026

- Read the original Option A and Option B `result.json`, `nmap-validation.xml`, and `SHA256SUMS`, plus Option A `scope.json`. These text artifacts show private Docker-lab addresses and MAC addresses, not obviously public credentials or student identifiers. Option B `scope.json` could not be fetched in this pass due to a transient connection error.
- The original `experiment.pcap` files were decoded and structurally inspected: Option A has 8 ARP frames (488 decoded bytes); Option B has 28 IPv4/TCP frames (2032 decoded bytes). Both parsed without truncated records. Option B's TCP frames had zero application payload bytes. No credential-bearing application content was observed; the captures still expose private lab IPs, MAC addresses, TCP ports and timestamps. **SHA-256 hashes have not yet been independently verified.**
- No original evidence files were copied into the public portfolio in this review. Copying evidence should wait until packet inspection, checksum verification and publication-authorisation checks are complete.
- No unit tests or automated secrets scans were executed in this pass.

