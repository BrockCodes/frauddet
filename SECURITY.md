# Security Policy — Leonard Governmental Investigative Toolkit (`frauddet`)

This project contains sensitive investigative and screening tooling intended primarily for use by governmental, regulatory, oversight, compliance, audit, and public-interest investigative entities operating in domains that may involve vulnerable populations, public funding, safety-critical service providers, or regulatory enforcement environments.

Because this software may be deployed in contexts where data includes confidential records, protected personal information, business licensure identifiers, historical enforcement references, or operational metadata tied to investigative workflows, all users are expected to follow strict standards for:

- operational security  
- data-handling and storage  
- ethical deployment  
- confidentiality and access control  
- disclosure discipline and investigative restraint  

Use of this software is governed by the **Leonard Governmental Investigative Software License v1.0**, including all restrictions, indemnifications, prohibitions, royalty terms, and user responsibilities. Operation of this software implies acknowledgement that improper deployment can impose material risk to individuals, agencies, operators, and affected third parties.

This security policy supplements the License and applies to all authorized users, evaluators, and commercial operators.

## Supported Security Posture

The project is provided **as-is** and without warranty (see License). However, the Author actively accepts and prioritizes:

- Good-faith vulnerability and security reports  
- Responsible disclosure submissions  
- Reports of misuse, discriminatory deployment, or abusive usage patterns  
- Concerns regarding privacy exposure, inference risk, or redaction bypass  
- Evidence of unpermitted bundling or commercial embedding of the Software  
- Reports of unsafe rule configurations or algorithmic misuse in operational settings  

Security and ethical-risk reports are treated as **higher priority than feature requests, enhancement proposals, or general development questions**.

This Software is designed to support **screening and triage**, not public accusation, fully automated enforcement, or conclusive fraud designation. Misuse that bypasses human review or due-process standards is considered a security-relevant risk condition.

## Responsible Disclosure Policy

If you believe you have identified:

- a software vulnerability  
- insecure behavior or data-handling pathway  
- an inference vector that may expose PII  
- a configuration pattern that creates material risk  
- a logic or output condition that could enable abuse or targeting  
- or a weakness that could harm providers, consumers, or investigative subjects  

you must report it privately and **must not publish or broadly disclose the issue** until remediation guidance or coordinated advisory processes are complete.

Uncoordinated disclosure may:

- enable harmful exploitation  
- disrupt active investigations  
- jeopardize enforcement integrity  
- expose protected entities or vulnerable individuals  
- facilitate retaliation, harassment, or doxxing  
- violate confidentiality obligations or applicable law  

### Do Not:

- Open public GitHub issues describing vulnerabilities  
- Share attack instructions or proof-of-concept exploits  
- Demonstrate impact using live systems or real populations  
- Use findings to probe, stress test, or profile external providers  
- Perform adversarial testing against production deployments  
- Leverage security findings for personal, political, or commercial gain  

Reports must be submitted **in good faith** and with **no unlawful data acquisition** or unauthorized access to third-party systems.

## How to Report a Security Issue

Submit reports privately via:

**Primary Security Contact**  
`brockleonard.ml@gmail.com`

If safely possible, include:

- a clear and direct summary of the issue  
- affected feature, module, or deployment area  
- reproduction steps **without transmitting sensitive datasets**  
- whether real-world data or production assets were involved  
- severity assessment or potential impact classification  
- environment details (OS, runtime, deployment mode, commit hash, branch)  

If screenshots, logs, or files contain PII, protected records, or identifiers:

- redact prior to submission  
- replace with anonymized examples where possible  
- indicate whether the full dataset must remain under custody control  

Encrypted communication can be arranged upon request.

Reports received from public sector agencies may be processed using structured advisory workflows or restricted-access channels where necessary.

## Scope of Security Review

The following are considered **in-scope** for responsible disclosure:

- PII and identity-redaction pathways  
- edge-case leakage under export or transformation handling  
- MongoDB persistence and metadata exposure risks  
- cross-run traceability behaviors and chain-of-custody assumptions  
- unintended identifier persistence during serialization  
- inference-based de-anonymization risks  
- poorly documented rule-interaction risk scenarios  
- unsafe default configurations likely to occur in field deployments  

The following areas are generally **out-of-scope** unless tied to systemic risk:

- local user error or isolated deployment misconfiguration  
- operational policies or IT controls outside the Software’s control boundary  
- theoretical vulnerabilities without actionable exploitation vectors  
- academic or speculative adversarial-modeling exercises  
- performance optimization concerns  
- stylistic, ergonomic, or developer experience feedback  
- issues arising only in forks, rewrites, or third-party modifications  

However, reports demonstrating **credible real-world harm potential** will be treated as in-scope regardless of strict technical boundary.

## Misuse, Abuse, and Ethical-Risk Reporting

Because the Software may influence investigative decision-making or risk prioritization, the following are treated as **security-relevant misuse conditions** and should be reported:

- use of outputs to harass or intimidate individuals  
- doxxing or publication of identities without lawful basis  
- deployment as a fully-automated adverse-decision system  
- discriminatory targeting or biased enforcement practices  
- use for political retaliation or adversarial monitoring  
- application outside `.gov` or approved commercial contexts  
- retaliation or sanctions actions based solely on automated flags  
- bundling inside third-party systems without declared royalties  
- attempts to obscure commercial-revenue attribution  
- obfuscation of derivative project lineage or authorship  

Reports submitted anonymously will still be reviewed.

## Data Handling & Confidentiality Expectations

Operators of this Software are expected to maintain disciplined controls including:

- restricted access to raw ingestion inputs  
- explicit separation between **internal** and **redacted** datasets  
- encryption of MongoDB connections and stored data  
- network-segmented database deployments  
- role-based authorization for investigative records  
- audit logging of access, export, and modification actions  
- prevention of plaintext credential storage  
- backup procedures compliant with institutional retention rules  

Chain-of-custody expectations include:

- stable `_run_id` and `_tag` metadata preservation  
- traceable run history and code-version lineage  
- change-controlled rule updates  
- clear record of who reviewed investigative outputs  
- preservation of original datasets when required by policy or law  

Failure to implement basic safeguards may constitute **negligent misuse under the License** and may expose users to indemnification liability.

## Third-Party Integrations & Dependencies

Security concerns may also arise from:

- enrichment APIs  
- vendor data sources  
- external record registries  
- geospatial or mapping services  
- scraping connectors  
- containerization pipelines  
- orchestration and scheduling layers  
- downstream analytics systems  

If a vulnerability relates to an external dependency, please include:

- dependency name and version  
- integration boundary  
- reproduction path  
- whether the issue is environmental or systemic  

Derivative deployments, forks, or modified pipelines:

- remain solely the responsibility of their operator  
- are not warranted or supported by the Author  
- may increase risk if redaction or logic is altered  
- do not transfer liability or guarantee safety  

Any suggestions, configuration changes, or local policy extensions implemented by third parties are made **at their own discretion and their own risk**.

The Author does not indemnify or assume responsibility for:

- third-party enforcement outcomes  
- modified scoring logic  
- altered redaction behavior  
- alternative data source integrations  
- expanded usage outside the intended investigative scope  

## Coordinated Response Process

Upon receiving a valid security or misuse report:

1. Receipt will be acknowledged within a reasonable timeframe.  
2. A preliminary triage and severity classification will be conducted.  
3. Additional clarifications may be requested under confidentiality.  
4. If necessary, mitigation guidance may be issued to affected operators.  
5. If the issue is systemic, an advisory or patched release may be prepared.  
6. Public disclosure — if appropriate — will only occur after mitigation coordination.

In cases involving:

- risk to vulnerable populations  
- exposure of regulated or licensed entities  
- potential retaliation or harassment  
- operational safety or welfare concerns  

response prioritization may be accelerated.

The Author reserves the right to:

- coordinate directly with government agencies  
- consult subject-matter experts  
- notify impacted partners when necessary  
- decline disclosure publication where public exposure increases risk  

## Legal & License Notice

Use of this Software requires:

- compliance with all terms of the License  
- lawful and ethical investigative use  
- internal review and verification of outputs  
- avoidance of harassment, targeting, or discriminatory outcomes  
- explicit user assumption of risk when modifying or integrating the Software  

Unauthorized:

- commercial use  
- embedding or bundling  
- license circumvention  
- removal of attribution  
- bypassing royalty obligations  
- concealment of derivative lineage  

is strictly prohibited and may result in enforcement and civil action.

See:
# SPDX-License-Identifier: LicenseRef-Leonard-Gov-Investigative-1.0

## Security & Licensing Contact

For:

- security vulnerabilities  
- misuse or ethical-risk incidents  
- privacy or inference-exposure concerns  
- licensing compliance or commercial use questions  
- deployment safety or investigative-risk consultation  

Contact:

**Garrett Leonard**  
Email: `brockleonard.ml@gmail.com`  
LinkedIn: https://www.linkedin.com/in/brockleonard

Thank you for supporting responsible, careful, and security-conscious use of this investigative software.
