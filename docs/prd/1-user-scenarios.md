# 1\. User Scenarios

## 1.1 PSIRT Member Writing a Vulnerability Advisory

  * **Available information:** Collection of bug reports and issue summaries; access to developers
  * **Background knowledge:** General vulnerability types, programming concepts
  * **Time pressure:** High
  * **Correctness vs. completeness:** Needs accurate CWE IDs; may prioritize speed when multiple weaknesses exist

## 1.2 Developer Fixing a Vulnerability

  * **Available information:** Source code, mistake and patch details, bug reports, tradeoff discussions, testing results, proof-of-concept code
  * **Background knowledge:** Programming languages, protocols, tech stacks, bug remediation
  * **Time pressure:** High
  * **Correctness importance:** Lower (primary focus on fixing bugs/features)
  * **Special consideration:** Developer may receive CWE IDs from external reports or tools

## 1.3 Academic Vulnerability Researcher

  * **Available information:** May lack source code or patch; research focus varies (single weakness class, technology-specific, detection methods)
  * **Background knowledge:** Varies with research orientation; deeper source understanding for exploit reliability
  * **Time pressure:** Low
  * **Correctness importance:** Moderate

## 1.4 Bug Bounty Hunter Reporting Vulnerabilities

  * **Available information:** May lack source code or patch; exploit writing may require deep technical insight
  * **Background knowledge:** Varies by attacker focus
  * **Time pressure:** Low
  * **Correctness importance:** Moderate

## 1.5 Product Manager Preventing Weaknesses at Scale

  * **Goal:** Identify common CWE patterns across products to guide large-scale remediation and prevention efforts
  * **Constraints:** Balances strategic planning with resource allocation
