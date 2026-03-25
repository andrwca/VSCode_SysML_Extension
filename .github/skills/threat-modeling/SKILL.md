---
name: threat-modeling
description: "Security Threat Modeling knowledge base for SysML v2 threat models. Contains all known threats, mitigations, and their mappings to ThreatModelToolbox SysML types. USE FOR: threat modeling, security analysis, identifying threats for components, generating SysML threat models, recommending mitigations, STRIDE analysis, security plan creation, threat identification for web apps, AI/LLM systems, containers, data stores, DevOps pipelines. DO NOT USE FOR: general Azure deployment, infrastructure provisioning, non-security topics."
---

# ISE Security Threat Modeling Skill

This skill contains the complete ISE Security Threat & Design Recommendations knowledge base, mapped to fully qualified SysML v2 paths in the `ThreatModelToolbox` package. Use this when generating or reviewing SysML threat models.

## How to Use This Skill

When the user asks to threat-model an architecture described in SysML:

1. Identify which **component types** (`part def`) and **flow types** (`item def`) are present in their model
2. Look up the matching threats from the catalogue below
3. Generate `concern` blocks (typed `ThreatModelToolbox::Threat`) with `subject :>> target` pointing to the relevant part or flow in the user's model
4. Generate `requirement` blocks (typed `ThreatModelToolbox::SecurityRequirement`) with `subject :>> target` pointing to the threat concern
5. Use the STRIDE category, severity, and likelihood from the catalogue

## SysML Pattern for Threats

```sysml
concern <threatName> : ThreatModelToolbox::Threat {
    doc /* <description> */
    subject :>> target = <path.to.component.or.flow>;
    :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::<category>;
    :>> severity = ThreatModelToolbox::SeverityKind::<level>;
    :>> likelihood = ThreatModelToolbox::LikelihoodKind::<level>;
    :>> targetDescription = "<human-readable target>";
}
```

## SysML Pattern for Mitigations

```sysml
requirement <mitigationName> : ThreatModelToolbox::SecurityRequirement {
    doc /* <description> */
    subject :>> target = threats.<threatName>;
    :>> isImplemented = false;
}
```

---

# Threat Catalogue

Each threat below lists:
- **Category**: The domain grouping (AI, Applications, Containers, Data Stores, DevOps, General)
- **STRIDE**: The primary STRIDE classification(s)
- **Applies To**: Fully qualified SysML `ThreatModelToolbox` types this threat targets
- **Threat**: Description of the threat
- **Mitigations**: Recommended security controls

---

## Category: AI / LLM

### T-AI-01: Excessive Agency

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`, `ThreatModelToolbox::StrideCategoryKind::elevationOfPrivilege`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::ExternalSystem`
- **Principle**: Confidentiality and Integrity
- **Threat**: Excessive Agency is the vulnerability that enables damaging actions to be performed in response to unexpected/ambiguous outputs from an LLM. When LLM agents have overly broad tool access or permissions, unintended or manipulated outputs can trigger harmful downstream actions.
- **Mitigations**:
  1. Limit the plugins/tools that LLM agents are allowed to call to only the minimum functions necessary
  2. Limit the functions implemented in LLM plugins/tools to the minimum necessary
  3. Avoid open-ended functions where possible
  4. Limit the permissions that LLM plugins/tools are granted to other systems to the minimum necessary
  5. Track user authorization and security scope to ensure actions are executed in the context of that specific user with minimum privileges
  6. Utilize human-in-the-loop control to require a human to approve all actions before they are taken
  7. Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed; enforce the complete mediation principle

### T-AI-02: Information Disclosure (LLM)

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::ExternalSystem`, `ThreatModelToolbox::HttpResponse`
- **Principle**: Confidentiality and Privacy
- **Threat**: LLM applications have the potential to reveal sensitive information, proprietary algorithms, or other confidential details through their output. This can result in unauthorized access to sensitive data, intellectual property, privacy violations, and other security breaches.
- **Mitigations**:
  1. Integrate adequate data sanitization and scrubbing techniques to prevent user data from entering the training model data
  2. Implement robust input validation and sanitization methods to identify and filter out potential malicious inputs
  3. When enriching/fine-tuning the model, apply the rule of least privilege — do not train on information that lower-privileged users should not see
  4. Access to external data sources (orchestration of data at runtime) should be limited
  5. Apply strict access control methods to external data sources and maintain a secure supply chain

### T-AI-03: Insecure Output Handling

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::HttpResponse`
- **Principle**: Confidentiality
- **Threat**: Insufficient validation, sanitization, and handling of LLM-generated outputs before they are passed downstream to other components and systems. Since LLM-generated content can be controlled by prompt input, this provides users indirect access to additional functionality, potentially leading to unintended code execution.
- **Mitigations**:
  1. Treat the model as any other user — adopt a zero-trust approach and apply proper input validation on responses coming from the model to backend functions
  2. Follow best practices for effective input validation and sanitization
  3. Encode model output back to users to mitigate undesired code execution by JavaScript or Markdown
  4. Ensure pydantic-style validation of LLM outputs (including semantic validation); take corrective actions when validation fails; enforce structure and type guarantees (e.g. JSON)
  5. Use Azure AI Content Safety Filters for prompt inputs and responses

### T-AI-04: Model Denial of Service

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::denialOfService`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::Gateway`, `ThreatModelToolbox::AzureAPIManagement`, `ThreatModelToolbox::HttpRequest`
- **Principle**: Availability
- **Threat**: An attacker interacts with an LLM in a method that consumes an exceptionally high amount of resources, resulting in a decline in quality of service and potentially incurring high resource costs. This can also be caused by supply chain vulnerabilities.
- **Mitigations**:
  1. Implement input validation and sanitization to ensure user input adheres to defined limits
  2. Cap resource use per request or step — requests involving complex parts should execute more slowly
  3. Enforce API rate limits to restrict requests per user or IP within a specific time frame
  4. Limit the number of queued and total actions in a system reacting to LLM responses
  5. Continuously monitor resource utilization to identify abnormal spikes or patterns
  6. Set strict input limits based on the LLM's context window
  7. All services within the Azure Trust Boundary must authenticate all incoming requests
  8. Use Azure Managed Identities to authenticate services where available
  9. For authorization, use Azure RBAC and conditional access policies with least privilege

### T-AI-05: Model Theft

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::unlikely`
- **Applies To**: `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::ExternalSystem`
- **Principle**: Confidentiality
- **Threat**: Proprietary LLM models are compromised, physically stolen, copied, or weights and parameters are extracted to create a functional equivalent. Users may also modify system-level prompt restrictions to "jailbreak" the LLM.
- **Mitigations**:
  1. Implement strong access controls and authentication mechanisms to limit unauthorized access to LLM model repositories and training environments
  2. Restrict the LLM's access to network resources, internal services, and APIs
  3. Regularly monitor and audit access logs related to LLM model repositories
  4. Automate MLOps deployment with governance, tracking, and approval workflows
  5. Rate-limit API calls where applicable
  6. Encrypt all customer or confidential data at rest using AES-256, AES-192, or AES-128

### T-AI-06: Overreliance

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::medium`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::HttpResponse`
- **Principle**: Integrity
- **Threat**: Overreliance occurs when an LLM produces erroneous information and provides it in an authoritative manner, leading to downstream decisions based on hallucinated or incorrect output.
- **Mitigations**:
  1. Regularly monitor and review LLM outputs; use self-consistency or voting techniques to filter inconsistent text
  2. Cross-check LLM output with trusted external sources
  3. Enhance the model with fine-tuning or embeddings to improve output quality
  4. Implement automatic validation mechanisms that cross-verify generated output against known facts
  5. Break down complex tasks into manageable subtasks assigned to different agents
  6. Communicate the risks and limitations associated with using LLMs
  7. Build APIs and user interfaces that encourage responsible use — content filters, user warnings, and clear labeling of AI-generated content
  8. Establish secure coding practices when using LLMs in development environments

### T-AI-07: Prompt Injection

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::spoofing`, `ThreatModelToolbox::StrideCategoryKind::tampering`, `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::ExternalSystem`, `ThreatModelToolbox::HttpRequest`
- **Principle**: Confidentiality, Integrity, Availability and Privacy
- **Threat**: Users can modify system-level prompt restrictions to "jailbreak" the LLM. Direct prompt injections overwrite or reveal the underlying system prompt. Indirect prompt injections occur when LLM accepts input from external sources (websites, files) that contain embedded malicious prompts.
- **Mitigations**:
  1. Enforce privilege control on LLM access to backend systems
  2. Segregate external content from user prompts; limit influence when untrusted content is used
  3. Manually monitor input and output periodically to check it is as expected
  4. Maintain fine user control on decision-making capabilities by LLM
  5. Encrypt all data in transit using approved cryptographic protocols
  6. Use Azure AI Content Safety Filters for prompt inputs and responses
  7. Use TLS 1.2 or TLS 1.3 with ECDHE-based cipher suites and NIST curves; enable HSTS

### T-AI-08: Supply Chain Vulnerabilities (LLM)

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::ExternalSystem`, `ThreatModelToolbox::AzureContainerRegistry`
- **Principle**: Confidentiality, Integrity and Availability
- **Threat**: Vulnerabilities in open source/third party packages used for development could lead to exploitation. This includes vulnerabilities in software components, training data, ML models, or deployment platforms.
- **Mitigations**:
  1. Use Azure Artifacts to publish and control feeds — lower risk of supply chain vulnerability
  2. Carefully vet data sources and suppliers, including T&Cs and privacy policies
  3. Only use reputable plugins; test them for your application requirements
  4. Maintain an up-to-date inventory of components using a Software Bill of Materials (SBOM)
  5. Use MLOps best practices and platforms with secure model repositories for data, model, and experiment tracking
  6. Use model and code signing when using external models and suppliers
  7. Apply anomaly detection and adversarial robustness tests on supplied models and data
  8. Implement sufficient monitoring for component and environment vulnerability scanning
  9. Implement a patching policy for vulnerable or outdated components
  10. Regularly review and audit supplier security and access

### T-AI-09: Training Data Poisoning

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::unlikely`
- **Applies To**: `ThreatModelToolbox::AzureOpenAI`, `ThreatModelToolbox::AzureCognitiveServices`, `ThreatModelToolbox::DataStore`, `ThreatModelToolbox::AzureBlobStorage`
- **Principle**: Integrity
- **Threat**: Manipulation of pre-training data or data involved in fine-tuning or embedding processes to introduce vulnerabilities, backdoors, or biases that could compromise model security, effectiveness, or ethical behavior.
- **Mitigations**:
  1. Verify the supply chain of training data; maintain attestations via ML-BOM methodology
  2. Verify legitimacy of data sources during pre-training, fine-tuning, and embedding stages
  3. Craft different models via separate training data for different use-cases
  4. Ensure sufficient sandboxing through network controls to prevent unintended data scraping
  5. Use strict vetting or input filters for training data; apply statistical outlier detection and anomaly detection
  6. Apply adversarial robustness techniques such as federated learning
  7. Use MLSecOps approach with adversarial robustness in the training lifecycle
  8. Test and detect by measuring loss during training; analyze trained models for poisoning signs
  9. Monitor and alert on the number of skewed responses exceeding a threshold
  10. Use human-in-the-loop to review responses and auditing

---

## Category: Applications

### T-APP-01: Multitenant Data Isolation Breach

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`, `ThreatModelToolbox::StrideCategoryKind::tampering`, `ThreatModelToolbox::StrideCategoryKind::denialOfService`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::DataStore`, `ThreatModelToolbox::AzureSQLDatabase`, `ThreatModelToolbox::AzureCosmosDB`, `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureAppService`
- **Principle**: Confidentiality, Integrity and Availability
- **Threat**: In multi-tenancy environments, malicious or compromised tenants might exploit vulnerabilities to access, modify, or disrupt data and services of other tenants, leading to data leaks, unauthorized data manipulation, and service interruptions.
- **Mitigations**:
  1. **Data Isolation**: Implement tenant-level data isolation (separate storage containers or schema separations); apply Row-Level Security (RLS) and Data Masking
  2. **API Security**: Implement API tenant context checks; validate tenant-specific tokens and claims using OAuth Scopes and Claims
  3. **Service Isolation**: Adopt tenant-aware application design; implement resource throttling per tenant
  4. **Monitoring**: Develop tenant-specific monitoring tagged with tenant identifiers; implement anomaly detection for unusual activities
  5. **Backup**: Establish isolated backup strategies per tenant; test tenant-specific restore procedures

### T-APP-02: Web Application Header Exploitation

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`, `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureAppService`, `ThreatModelToolbox::AzureFunctions`, `ThreatModelToolbox::Gateway`, `ThreatModelToolbox::AzureApplicationGateway`, `ThreatModelToolbox::AzureFrontDoor`, `ThreatModelToolbox::HttpRequest`, `ThreatModelToolbox::HttpResponse`
- **Principle**: Confidentiality and Integrity
- **Threat**: Attackers might exploit vulnerabilities by intercepting and manipulating communication between client and server, or exploiting resources improperly loaded from third party domains due to missing security headers.
- **Mitigations**:
  1. **HSTS**: Enforce HTTPS via HSTS header; set adequate max-age; include subdomains
  2. **CSP**: Define allowed source domains; limit resource types; use frame-ancestors directive; use report-uri/report-to for violation detection
  3. **X-Content-Type-Options**: Set to `nosniff` to prevent MIME type confusion
  4. **Monitoring**: Implement monitoring and alerting for header violations; regularly audit and adjust policies

---

## Category: Containers

### T-CON-01: Container Image Vulnerabilities

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::AzureContainerApps`, `ThreatModelToolbox::AzureKubernetesService`, `ThreatModelToolbox::AzureContainerRegistry`, `ThreatModelToolbox::Component`
- **Principle**: Integrity
- **Threat**: Container images may contain unknown vulnerabilities, security issues, and malicious applications.
- **Mitigations**:
  1. Only run containers from trusted registries; when using ACR, enable Azure Defender to scan container images on push
  2. Use container scanning tools within CI/CD pipelines to detect vulnerabilities earlier
  3. Use Microsoft Defender for Containers to secure clusters, containers, and applications

---

## Category: Data Stores

### T-DATA-01: User Data Deletion Non-Compliance

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::repudiation`
- **Severity**: `ThreatModelToolbox::SeverityKind::medium`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::DataStore`, `ThreatModelToolbox::AzureSQLDatabase`, `ThreatModelToolbox::AzureCosmosDB`, `ThreatModelToolbox::AzureBlobStorage`, `ThreatModelToolbox::AzureTableStorage`
- **Principle**: Privacy
- **Threat**: The application does not allow the deletion of a user's profile from storage, potentially violating regulatory requirements (GDPR, etc.).
- **Mitigations**:
  1. If required by regulation, implement the ability to delete a user's profile and all associated data from all datastores

### T-DATA-02: Direct Attack on Data Store

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::DataStore`, `ThreatModelToolbox::AzureSQLDatabase`, `ThreatModelToolbox::AzureCosmosDB`, `ThreatModelToolbox::AzureBlobStorage`, `ThreatModelToolbox::AzurePostgreSQL`, `ThreatModelToolbox::AzureMySQL`, `ThreatModelToolbox::AzureRedisCache`, `ThreatModelToolbox::AzureDataLakeStorage`
- **Principle**: Confidentiality
- **Threat**: Data is a valuable target; attacking the data store directly (rather than during transit) allows data exfiltration at a much larger scale.
- **Mitigations**:
  1. Encrypt all customer or confidential data at rest using AES-256, AES-192, or AES-128
  2. Leverage SQL TDE whenever available
  3. Encryption must be enabled before writing data to storage
  4. Azure Storage, Cosmos DB, Azure SQL Database, and Azure Database for MySQL encryption for data at rest uses AES-256 and is always on
  5. TDE with service-managed keys is enabled by default for Azure SQL
  6. Azure SQL Database backup data is automatically encrypted with Azure platform-managed keys
  7. If using IaC, ensure configuration files are stored in a storage account, not in the repository

### T-DATA-03: Malicious Files

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::DataStore`, `ThreatModelToolbox::AzureBlobStorage`, `ThreatModelToolbox::AzureDataLakeStorage`
- **Principle**: Integrity
- **Threat**: Malicious files can compromise cloud applications and will continue to be an issue if they persist on file storage and databases.
- **Mitigations**:
  1. Scan all files before uploading to non-compute Azure resources
  2. Scans should cover all files
  3. Access to unscanned files should be locked down until proof of safety is generated
  4. Generate persistent evidence for compliance and security operations purposes

---

## Category: DevOps

### T-DEV-01: CI/CD Secrets Exposure

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::AzureDevOps`, `ThreatModelToolbox::ExternalSystem`
- **Principle**: Confidentiality and Integrity
- **Threat**: CI/CD Pipelines may contain or leak sensitive information (secrets, keys, credentials) in plaintext.
- **Mitigations**:
  1. Cleanse all secrets, key materials, and credentials stored in CI/CD Pipelines
  2. Add pre-commit checks to ensure a secure pipeline cleansed of sensitive artifacts

### T-DEV-02: Code Vulnerabilities and Leaked Secrets

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`, `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::AzureDevOps`, `ThreatModelToolbox::ExternalSystem`
- **Principle**: Confidentiality and Integrity
- **Threat**: Source code might contain vulnerabilities and sensitive information (secrets, passwords, keys).
- **Mitigations**:
  1. Add static code analysis tools (SAST) in CI/CD pipelines to detect vulnerabilities and gate insecure code from production
  2. Add dependency and supply chain scanning to ensure current and secure libraries
  3. Add credential scanning to CI/CD pipelines to prevent secret leakage

---

## Category: General (Applies to All Architectures)

### T-GEN-01: Broken or Non-Existent Authentication

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::spoofing`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureAppService`, `ThreatModelToolbox::AzureFunctions`, `ThreatModelToolbox::AzureContainerApps`, `ThreatModelToolbox::AzureKubernetesService`, `ThreatModelToolbox::Gateway`
- **Principle**: Confidentiality
- **Threat**: Broken or non-existent authentication mechanisms may allow attackers to gain access to confidential information.
- **Mitigations**:
  1. All services within the Azure Trust Boundary must authenticate all incoming requests, including from the same network
  2. Use Azure AD authentication for centralized identity management
  3. Use Azure Managed Identities where available; use Service Principals if not supported
  4. External users/services may use Username + Passwords, Tokens, or Certificates (stored in Key Vault)
  5. Use Azure RBAC to segregate duties and grant least-privilege access
  6. Leverage AAD PIM for administrative access
  7. Avoid storing secrets in databases or configuration files

### T-GEN-02: Compromising Publicly Exposed Services

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::spoofing`, `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::AzureAppService`, `ThreatModelToolbox::AzureFunctions`, `ThreatModelToolbox::Gateway`, `ThreatModelToolbox::AzureAPIManagement`
- **Principle**: Confidentiality and Integrity
- **Threat**: A large attack surface — particularly internet-exposed services — increases the probability of compromise.
- **Mitigations**:
  1. Use strong network controls: Azure Virtual Networks, NSGs, or Private Endpoints
  2. Use Azure Private Endpoints to block all internet connections to services that do not need to be publicly exposed
  3. Turn on Azure Defender for a list of vulnerabilities associated with your subscription

### T-GEN-03: Distributed Denial of Service (DDoS)

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::denialOfService`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::Gateway`, `ThreatModelToolbox::AzureApplicationGateway`, `ThreatModelToolbox::AzureFrontDoor`, `ThreatModelToolbox::AzureLoadBalancer`, `ThreatModelToolbox::AzureDDoSProtection`
- **Principle**: Availability
- **Threat**: DDoS attacks attempt to exhaust an application's resources, making it unavailable to legitimate users.
- **Mitigations**:
  1. Turn on Azure DDoS Protection
  2. All Azure services are protected with the DDoS Basic plan
  3. Upgrade to Standard plan for better support during active attacks

### T-GEN-04: Insufficient Logging and Monitoring

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::repudiation`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::MonitoringService`, `ThreatModelToolbox::AzureMonitor`, `ThreatModelToolbox::AzureApplicationInsights`, `ThreatModelToolbox::AzureLogAnalytics`, `ThreatModelToolbox::AzureSentinel`
- **Principle**: Integrity
- **Threat**: Insufficient logging and monitoring is the bedrock of nearly every major incident. Attackers rely on lack of monitoring to achieve their goals undetected.
- **Minimum Events to Log**:
  - Login/logout events
  - Password change events
  - Privilege delegation events
  - Security validation failures (input validation, authorization check failures)
  - Application errors and system events
  - Application/system startups, shutdowns, and logging initialization
- **Mitigations**:
  1. Implement a monitoring solution (Azure Monitor or Log Analytics) for web apps, security events, analytics, and workloads
  2. Implement Microsoft Sentinel as SIEM for incident management
  3. Use alerting systems for notifications requiring direct action
  4. Install Azure Monitor agent on critical VMs for event ingestion

### T-GEN-05: Man in the Middle (MitM)

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`, `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::HttpRequest`, `ThreatModelToolbox::HttpResponse`, `ThreatModelToolbox::Gateway`, `ThreatModelToolbox::AzureVPNGateway`, `ThreatModelToolbox::AzureVirtualNetwork`
- **Principle**: Confidentiality and Integrity
- **Threat**: Without encrypting data in transit, plaintext data could be intercepted via man-in-the-middle, downgrade, or cross-protocol attacks. Sensitive data could be exposed or tampered with.
- **Mitigations**:
  1. Use TLS to encrypt all HTTP-based network traffic; use IPSec for non-HTTP traffic containing customer or confidential data
  2. Use only TLS 1.2 or TLS 1.3; use ECDHE-based cipher suites and NIST curves; use strong keys; enable HSTS; turn off TLS compression; do not use ticket-based session resumption

### T-GEN-06: Secrets Leaking

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::SecretStore`, `ThreatModelToolbox::AzureKeyVault`, `ThreatModelToolbox::Credential`
- **Principle**: Confidentiality and Integrity
- **Threat**: Secrets leaking into unsecured locations are an easy way for adversaries to gain access. Secrets can be used to spoof owners or decrypt data.
- **Mitigations**:
  1. Never store secrets in code, configuration files, or databases — use a vault or secure container
  2. Separate application secrets by environment
  3. Rotate all secrets before turning over the application to the customer
  4. Store all secrets, encryption keys, and certificates in Key Vault
  5. Use multiple Key Vaults to separate secrets for different critical services
  6. Define and implement secrets rotation strategy; all vault items should have expiration dates

### T-GEN-07: Malicious or Unnecessary Traffic

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::likely`
- **Applies To**: `ThreatModelToolbox::Gateway`, `ThreatModelToolbox::AzureApplicationGateway`, `ThreatModelToolbox::AzureFrontDoor`, `ThreatModelToolbox::AzureFirewall`, `ThreatModelToolbox::AzureAPIManagement`, `ThreatModelToolbox::HttpRequest`
- **Principle**: Integrity
- **Threat**: Sending malicious or unnecessary traffic to Azure resources can lead to resource compromise or create a vector for bypassing other security controls.
- **Mitigations**:
  1. Use Application Gateway before publicly accessible Azure Services; enable WAF with Azure-managed rules (OWASP ruleset); define custom rules as needed
  2. Turn on DDoS Protection

### T-GEN-08: Software Supply Chain Integrity Compromises

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::tampering`
- **Severity**: `ThreatModelToolbox::SeverityKind::high`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::AzureDevOps`, `ThreatModelToolbox::ExternalSystem`, `ThreatModelToolbox::AzureContainerRegistry`
- **Principle**: Integrity
- **Threat**: Compromises to the software supply chain (packages, libraries, dependencies) can result in unauthorized access, malicious code execution, or disruption of critical systems.
- **Mitigations**:
  1. Create a Software Bill of Materials (SBOM) with every release to document dependencies and track bugs, malicious code, or known breaches
  2. Cryptographically sign releases and related artifacts (SBOMs, vulnerability scans); verify signatures before running

### T-GEN-09: Subversion of Authorization Controls

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::elevationOfPrivilege`
- **Severity**: `ThreatModelToolbox::SeverityKind::critical`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::Component`, `ThreatModelToolbox::WebApplication`, `ThreatModelToolbox::IdentityProvider`, `ThreatModelToolbox::AzureEntraID`, `ThreatModelToolbox::AzureManagedIdentity`
- **Principle**: Confidentiality
- **Threat**: Authorization controls could be subverted to allow an authenticated user/service to access unauthorized information or elevate privileges.
- **Mitigations**:
  1. Use Azure RBAC to segregate duties and grant only least-privilege access at a particular scope
  2. Use Azure services role-based authorization feature
  3. Grant appropriate permissions and roles to service principals

### T-GEN-10: Unencrypted Internal Network Traffic

- **STRIDE**: `ThreatModelToolbox::StrideCategoryKind::informationDisclosure`
- **Severity**: `ThreatModelToolbox::SeverityKind::medium`
- **Likelihood**: `ThreatModelToolbox::LikelihoodKind::possible`
- **Applies To**: `ThreatModelToolbox::AzureVirtualNetwork`, `ThreatModelToolbox::HttpRequest`, `ThreatModelToolbox::HttpResponse`, `ThreatModelToolbox::DatabaseQuery`, `ThreatModelToolbox::DatabaseResult`
- **Principle**: Confidentiality and Integrity
- **Threat**: Unencrypted network traffic within the tenant boundary may cause compliance issues if it contains sensitive data.
- **Mitigations**:
  1. Use TLS to encrypt all HTTP-based network traffic; use IPSec for non-HTTP traffic containing customer or confidential data
  2. Use only TLS 1.2 or TLS 1.3; use ECDHE-based cipher suites and NIST curves; use strong keys; enable HSTS; turn off TLS compression; do not use ticket-based session resumption

---

## Quick Reference: Component → Applicable Threats

Use this table to quickly identify which threats apply when a given `ThreatModelToolbox` component type appears in a user's architecture.

| SysML Type (fully qualified) | Applicable Threats |
|---|---|
| `ThreatModelToolbox::WebApplication` | T-AI-02, T-AI-03, T-AI-06, T-APP-01, T-APP-02, T-GEN-01, T-GEN-02, T-GEN-03, T-GEN-09 |
| `ThreatModelToolbox::AzureAppService` | T-APP-01, T-APP-02, T-GEN-01, T-GEN-02 |
| `ThreatModelToolbox::AzureFunctions` | T-APP-02, T-GEN-01, T-GEN-02 |
| `ThreatModelToolbox::AzureOpenAI` | T-AI-01 through T-AI-09 |
| `ThreatModelToolbox::AzureCognitiveServices` | T-AI-01 through T-AI-09 |
| `ThreatModelToolbox::DataStore` | T-APP-01, T-DATA-01, T-DATA-02, T-DATA-03, T-AI-09 |
| `ThreatModelToolbox::AzureSQLDatabase` | T-APP-01, T-DATA-01, T-DATA-02 |
| `ThreatModelToolbox::AzureCosmosDB` | T-APP-01, T-DATA-01, T-DATA-02 |
| `ThreatModelToolbox::AzureBlobStorage` | T-DATA-01, T-DATA-02, T-DATA-03, T-AI-09 |
| `ThreatModelToolbox::AzureContainerApps` | T-CON-01, T-GEN-01 |
| `ThreatModelToolbox::AzureKubernetesService` | T-CON-01, T-GEN-01 |
| `ThreatModelToolbox::AzureContainerRegistry` | T-CON-01, T-AI-08, T-GEN-08 |
| `ThreatModelToolbox::Gateway` | T-APP-02, T-GEN-01, T-GEN-03, T-GEN-05, T-GEN-07 |
| `ThreatModelToolbox::AzureApplicationGateway` | T-APP-02, T-GEN-03, T-GEN-07 |
| `ThreatModelToolbox::AzureFrontDoor` | T-APP-02, T-GEN-03, T-GEN-07 |
| `ThreatModelToolbox::AzureAPIManagement` | T-AI-04, T-GEN-02, T-GEN-07 |
| `ThreatModelToolbox::IdentityProvider` | T-GEN-09 |
| `ThreatModelToolbox::AzureEntraID` | T-GEN-09 |
| `ThreatModelToolbox::SecretStore` | T-GEN-06 |
| `ThreatModelToolbox::AzureKeyVault` | T-GEN-06 |
| `ThreatModelToolbox::MonitoringService` | T-GEN-04 |
| `ThreatModelToolbox::AzureMonitor` | T-GEN-04 |
| `ThreatModelToolbox::AzureApplicationInsights` | T-GEN-04 |
| `ThreatModelToolbox::AzureLogAnalytics` | T-GEN-04 |
| `ThreatModelToolbox::AzureSentinel` | T-GEN-04 |
| `ThreatModelToolbox::AzureDevOps` | T-DEV-01, T-DEV-02, T-GEN-08 |
| `ThreatModelToolbox::ExternalSystem` | T-AI-01, T-AI-02, T-AI-08, T-DEV-01, T-DEV-02, T-GEN-08 |
| `ThreatModelToolbox::AzureVirtualNetwork` | T-GEN-05, T-GEN-10 |
| `ThreatModelToolbox::AzureDDoSProtection` | T-GEN-03 |
| `ThreatModelToolbox::AzureManagedIdentity` | T-GEN-09 |
| `ThreatModelToolbox::Component` (base) | T-CON-01, T-GEN-01 through T-GEN-10 |

## Quick Reference: Flow Type → Applicable Threats

| SysML Type (fully qualified) | Applicable Threats |
|---|---|
| `ThreatModelToolbox::HttpRequest` | T-AI-04, T-AI-07, T-APP-02, T-GEN-05, T-GEN-07, T-GEN-10 |
| `ThreatModelToolbox::HttpResponse` | T-AI-02, T-AI-03, T-AI-06, T-APP-02, T-GEN-05, T-GEN-10 |
| `ThreatModelToolbox::DatabaseQuery` | T-GEN-10 |
| `ThreatModelToolbox::DatabaseResult` | T-GEN-10 |
| `ThreatModelToolbox::Credential` | T-GEN-06 |
| `ThreatModelToolbox::AuthToken` | T-GEN-01, T-GEN-09 |

---

## Source

This threat catalogue is derived from the [ISE Security TD Recommendations](https://github.com/microsoft/ise-security-td-recommendations) repository maintained by the ISE Security Team. It covers threats across AI/LLM, Applications, Containers, Data Stores, DevOps, and General categories.
