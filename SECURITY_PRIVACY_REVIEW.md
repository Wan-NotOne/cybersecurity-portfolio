# Public Security & Privacy Review

**Scope:** This portfolio, the new curated public project folders, and a preliminary review of the original coursework sources.  
**Review date:** 19 November 2026  
**Status:** Targeted source, evidence, integrity, unit-test and Git-history secrets checks completed; not a comprehensive security assessment.

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
| PCAP files are included in both linked repositories | **Packet structure reviewed; publication authorised by coursework owner** | Original Option A and B captures were decoded and packet headers inspected on 19 November 2026. No application payload was present. Owner confirmed permission to publish reviewed evidence; SHA-256 comparison passed for both evidence sets. Packet inspection is not full security clearance. |
| GitHub file search returned no matches for sensitive-keyword queries | **Follow-up completed for tested local repository** | Gitleaks reported no leaks in 27 commits (140.67 KB scanned). Detection is rule-based and does not prove absence of all secrets. |
| Portfolio images and Google Fonts are served from third parties | **Privacy consideration** | Third-party hosts can receive visitors' IP addresses and request metadata. Consider self-hosting properly licensed image assets and system fonts; verify image availability and attribution/licensing. |
| Targeted local verification | **Completed with limitations** | 22/22 offline unit tests passed; Gitleaks reported no leaks. Dependency review, full static analysis and deployment configuration review remain outstanding. |

## Responsible disclosure and evidence handling

Only publish material that is authorised for public release. Before uploading screenshots, packet captures, JSON output, or network logs, review them for personal identifiers, authentication data, real infrastructure details, and third-party information. If sanitisation changes an evidence file, record the change and regenerate its SHA-256 checksum; retain an unmodified original only in a secure, access-controlled location where permitted.

## Verification status — 19 November 2026

The portfolio owner ran tests and checks locally and shared the terminal results:

| Verification | Observed result | Scope |
| --- | --- | --- |
| Network Device Discovery unit tests | **PASS — 9/9** | Python 3.12.2; offline mocked unit tests |
| TCP SYN Port Scanner unit tests | **PASS — 13/13** | Python 3.12.2; offline mocked unit tests |
| Option A evidence SHA-256 | **PASS** | Owner reported all four entries in `SHA256SUMS` matched locally |
| Option B evidence SHA-256 | **PASS** | Owner reported all four entries in `SHA256SUMS` matched locally |
| Gitleaks Git-history scan | **No leaks found** | Owner-reported output: 27 commits, approximately 140.67 KB, 413 ms |

The SHA-256 results were supplied by the owner after local file comparisons; this review does not independently attest to the execution environment. The Gitleaks result is limited to the repository and history scanned locally and the rules used by that tool. These checks do not establish that the site is free of all vulnerabilities, personal identifiers or privacy risks. A full dependency audit, comprehensive static analysis, review of all historical content and live deployment verification have not been completed.

## References

- [Portfolio](https://github.com/Wan-NotOne/cybersecurity-portfolio)
- [Public ARP project](projects/network-device-discovery/)
- [Public TCP SYN project](projects/tcp-syn-port-scanner/)

## Curated portfolio edition (current state)

The two public-edition project folders are present on `main`, and the live site's project cards link to these folders. The public project folders currently contain README, requirements, source code and unit-test files, but no `evidence/` directories. This does **not** remove information from separately published original coursework repositories. The curated source passed 22 offline unit tests locally and the owner reported a clean Gitleaks history scan. A full-tree identifier review and deployment review remain outstanding.

## Evidence review — 19 November 2026

- Read the original Option A and Option B `result.json`, `nmap-validation.xml`, and `SHA256SUMS`, plus Option A `scope.json`. These text artifacts show private Docker-lab addresses and MAC addresses, not obviously public credentials or student identifiers. Option B `scope.json` was subsequently fetched and checked; it describes the isolated authorised lab target and four allowed ports.
- The original `experiment.pcap` files were decoded and structurally inspected: Option A has 8 ARP frames (488 decoded bytes); Option B has 28 IPv4/TCP frames (2032 decoded bytes). Both parsed without truncated records. Option B's TCP frames had zero application payload bytes. No credential-bearing application content was observed; the captures still expose private lab IPs, MAC addresses, TCP ports and timestamps. The owner subsequently reported matching SHA-256 values for both full evidence manifests.
- No original evidence files were copied into the public portfolio in this review. Packet inspection, owner-reported checksum verification and owner authorisation have now been recorded. Evidence has not yet been copied into this public portfolio; publication should be accompanied by a final identifier review and provenance notes.
- Subsequently, the owner executed 22 offline unit tests (all passed) and a Gitleaks Git-history scan (no leaks found). See verification status above.

