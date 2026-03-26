package ThreatModelToolbox {
	doc /* A reusable library for threat modeling grounded in SysML v2 Systems Library types.
	     *
	     * Mapping to Systems Library:
	     *   Components      → part def   (structural elements that own ports)
	     *   Data in motion  → item def   (things that flow between parts)
	     *   Connection pts  → port def   (typed interaction points)
	     *   Structural links → interface def (connect ports on parts)
	     *   Threats         → concern def  (stakeholder worries with subject)
	     *   Mitigations     → requirement def (constraints on a subject)
	     *   Annotations     → metadata def (tag any element with STRIDE etc.)
	     *   Scenarios       → use case def (subject + actors)
	     *   Sequences       → occurrence def with messages */

	// ─── Enumerations ───

	enum def StrideCategoryKind {
		doc /* The STRIDE threat classification categories. */
		enum spoofing;
		enum tampering;
		enum repudiation;
		enum informationDisclosure;
		enum denialOfService;
		enum elevationOfPrivilege;
	}

	enum def SeverityKind {
		enum critical;
		enum high;
		enum medium;
		enum low;
		enum informational;
	}

	enum def LikelihoodKind {
		enum almostCertain;
		enum likely;
		enum possible;
		enum unlikely;
		enum rare;
	}

	enum def AuthenticationKind {
		enum none;
		enum apiKey;
		enum certificate;
		enum managedIdentity;
		enum oauthToken;
		enum saml;
	}

	enum def DataClassificationKind {
		enum public_;
		enum internal_;
		enum confidential;
		enum restricted;
	}

	enum def EncryptionKind {
		enum none;
		enum inTransit;
		enum atRest;
		enum both;
	}

	enum def ActorMotivationKind {
		enum financial;
		enum espionage;
		enum disruption;
		enum ideological;
		enum accidental;
	}

	enum def ActorCapabilityKind {
		enum nationState;
		enum organised;
		enum skilled;
		enum opportunistic;
		enum insider;
	}

	// ─── Item Definitions (things that flow) ───

	item def HttpRequest {
		doc /* An HTTP/HTTPS request flowing between components. */
		attribute method : ScalarValues::String;
		attribute isEncrypted : ScalarValues::Boolean;
	}

	item def HttpResponse {
		doc /* An HTTP/HTTPS response returned from a component. */
		attribute statusCode : ScalarValues::Integer;
		attribute isEncrypted : ScalarValues::Boolean;
	}

	item def AuthToken {
		doc /* An authentication or authorisation token. */
		attribute tokenType : AuthenticationKind;
	}

	item def DatabaseQuery {
		doc /* A query sent to a data store. */
		attribute isParameterised : ScalarValues::Boolean;
	}

	item def DatabaseResult {
		doc /* A result set returned from a data store. */
		attribute dataClassification : DataClassificationKind;
	}

	item def TelemetryPayload {
		doc /* Telemetry, logs, or metrics emitted by a component. */
	}

	item def Credential {
		doc /* A secret, connection string, key, or certificate. */
		attribute classification : DataClassificationKind;
	}

	// ─── Component Definitions (architectural building blocks) ───

	part component {

		abstract part def Component {
			doc /* Base definition for any processing element in the architecture. */
			attribute description : ScalarValues::String;
			attribute isPubliclyAccessible : ScalarValues::Boolean;
			attribute authentication : AuthenticationKind;
			attribute encryption : EncryptionKind;
		}

		part def WebApplication :> Component {
			doc /* A web application or API hosted on a compute platform. */
		}

		part def IdentityProvider :> Component {
			doc /* An identity and access management service (e.g. Microsoft Entra ID). */
		}

		part def DataStore :> Component {
			doc /* A persistent data store (SQL database, NoSQL, blob storage, etc.). */
			attribute dataClassification : DataClassificationKind;
		}

		part def SecretStore :> Component {
			doc /* A dedicated secret management service (e.g. Azure Key Vault). */
		}

		part def MonitoringService :> Component {
			doc /* A monitoring, logging, or telemetry aggregation service. */
		}

		part def Gateway :> Component {
			doc /* A network gateway, load balancer, or WAF. */
		}

		part def ExternalSystem :> Component {
			doc /* An external system or third-party service. */
		}

		// ─── Azure Resource Definitions (specialised components per Azure service) ───

		// ── Compute ──

		part def AzureAppService :> WebApplication {
			doc /* Azure App Service — managed PaaS for hosting web apps, REST APIs, and mobile backends. */
		}

		part def AzureFunctions :> WebApplication {
			doc /* Azure Functions — serverless event-driven compute service. */
		}

		part def AzureContainerApps :> Component {
			doc /* Azure Container Apps — managed container orchestration for microservices. */
		}

		part def AzureKubernetesService :> Component {
			doc /* Azure Kubernetes Service (AKS) — managed Kubernetes cluster. */
		}

		part def AzureVirtualMachine :> Component {
			doc /* Azure Virtual Machine — IaaS compute running Windows or Linux. */
		}

		// ── Networking ──

		part def AzureApplicationGateway :> Gateway {
			doc /* Azure Application Gateway — L7 load balancer with optional WAF. */
			attribute wafEnabled : ScalarValues::Boolean;
		}

		part def AzureFrontDoor :> Gateway {
			doc /* Azure Front Door — global entry point with CDN, WAF, and routing. */
			attribute wafEnabled : ScalarValues::Boolean;
		}

		part def AzureLoadBalancer :> Gateway {
			doc /* Azure Load Balancer — L4 load balancer for VMs and scale sets. */
		}

		part def AzureFirewall :> Gateway {
			doc /* Azure Firewall — managed cloud-native network security service. */
		}

		part def AzureVirtualNetwork :> Component {
			doc /* Azure Virtual Network (VNet) — isolated network for Azure resources. */
		}

		part def AzureDNS :> Component {
			doc /* Azure DNS — DNS hosting service for domain name resolution. */
		}

		part def AzureTrafficManager :> Gateway {
			doc /* Azure Traffic Manager — DNS-based traffic routing across regions. */
		}

		part def AzureCDN :> Component {
			doc /* Azure CDN — content delivery network for caching static assets. */
		}

		part def AzureVPNGateway :> Gateway {
			doc /* Azure VPN Gateway — encrypted cross-premises connectivity. */
		}

		part def AzurePrivateEndpoint :> Component {
			doc /* Azure Private Endpoint — private connectivity to Azure services over VNet. */
		}

		// ── Identity & Security ──

		part def AzureEntraID :> IdentityProvider {
			doc /* Microsoft Entra ID (Azure AD) — cloud identity and access management. */
		}

		part def AzureKeyVault :> SecretStore {
			doc /* Azure Key Vault — managed store for secrets, keys, and certificates. */
		}

		part def AzureDDoSProtection :> Component {
			doc /* Azure DDoS Protection — volumetric attack mitigation for VNets. */
		}

		part def AzureManagedIdentity :> Component {
			doc /* Azure Managed Identity — automatic credential management for service-to-service auth. */
		}

		// ── Data & Storage ──

		part def AzureSQLDatabase :> DataStore {
			doc /* Azure SQL Database — managed relational database (SQL Server engine). */
		}

		part def AzureCosmosDB :> DataStore {
			doc /* Azure Cosmos DB — globally distributed multi-model NoSQL database. */
		}

		part def AzureBlobStorage :> DataStore {
			doc /* Azure Blob Storage — object storage for unstructured data. */
		}

		part def AzureTableStorage :> DataStore {
			doc /* Azure Table Storage — NoSQL key-value store for structured data. */
		}

		part def AzureQueueStorage :> Component {
			doc /* Azure Queue Storage — simple message queuing between components. */
		}

		part def AzureRedisCache :> DataStore {
			doc /* Azure Cache for Redis — in-memory data store for caching and sessions. */
		}

		part def AzureDataLakeStorage :> DataStore {
			doc /* Azure Data Lake Storage Gen2 — scalable analytics-optimised storage. */
		}

		part def AzurePostgreSQL :> DataStore {
			doc /* Azure Database for PostgreSQL — managed PostgreSQL service. */
		}

		part def AzureMySQL :> DataStore {
			doc /* Azure Database for MySQL — managed MySQL service. */
		}

		// ── Integration & Messaging ──

		part def AzureServiceBus :> Component {
			doc /* Azure Service Bus — enterprise message broker with queues and topics. */
		}

		part def AzureEventHub :> Component {
			doc /* Azure Event Hubs — big-data streaming and event ingestion service. */
		}

		part def AzureEventGrid :> Component {
			doc /* Azure Event Grid — serverless event routing service. */
		}

		part def AzureAPIManagement :> Gateway {
			doc /* Azure API Management — API gateway with policies, rate limiting, and developer portal. */
		}

		part def AzureLogicApps :> Component {
			doc /* Azure Logic Apps — serverless workflow orchestration for integration scenarios. */
		}

		part def AzureSignalR :> Component {
			doc /* Azure SignalR Service — managed real-time messaging for web applications. */
		}

		// ── Monitoring & Observability ──

		part def AzureMonitor :> MonitoringService {
			doc /* Azure Monitor — platform-level monitoring, metrics, and alerting. */
		}

		part def AzureApplicationInsights :> MonitoringService {
			doc /* Application Insights — application performance monitoring and diagnostics. */
		}

		part def AzureLogAnalytics :> MonitoringService {
			doc /* Azure Log Analytics — centralised log collection and KQL-based querying. */
		}

		part def AzureSentinel :> MonitoringService {
			doc /* Microsoft Sentinel — cloud-native SIEM and SOAR for security operations. */
		}

		// ── AI & Cognitive ──

		part def AzureOpenAI :> ExternalSystem {
			doc /* Azure OpenAI Service — managed access to GPT and other foundation models. */
		}

		part def AzureCognitiveServices :> ExternalSystem {
			doc /* Azure Cognitive Services — pre-built AI APIs for vision, speech, language, and search. */
		}

		// ── DevOps & Governance ──

		part def AzureDevOps :> ExternalSystem {
			doc /* Azure DevOps — CI/CD pipelines, boards, repos, and artifact management. */
		}

		part def AzurePolicy :> Component {
			doc /* Azure Policy — governance engine enforcing organisational standards. */
		}

		part def AzureContainerRegistry :> DataStore {
			doc /* Azure Container Registry — managed Docker container image registry. */
		}
	}

	// ─── Threat Actor ───

	part def ThreatActor :> Actor {
		doc /* An entity that poses a threat to the system. */
		attribute motivation : ActorMotivationKind;
		attribute capability : ActorCapabilityKind;
	}

	part def Actor {
		doc /* An entity that acts on the system. */
		attribute description : ScalarValues::String;
	}

	// ─── Trust Boundary ───

	part def TrustBoundary {
		doc /* A logical boundary separating zones of differing trust levels. */
		attribute description : ScalarValues::String;
		part components[0..*] : Component;
	}

	// ─── Threat Concerns (threats modelled as stakeholder worries) ───

	concern def Threat {
		doc /* A threat identified against a component or data flow.
		     * The subject identifies the at-risk element.
		     * Inherits from Requirements::ConcernCheck, providing built-in
		     * subject, stakeholders, assumptions, and constraints. */
		subject target;
		attribute strideCategory : StrideCategoryKind;
		attribute severity : SeverityKind;
		attribute likelihood : LikelihoodKind;
		attribute targetDescription : ScalarValues::String;
	}

	// ─── Security Requirements (mitigations as constraints on a subject) ───

	requirement def SecurityRequirement {
		doc /* A security control or countermeasure that addresses a threat.
		     * The subject identifies the component being protected.
		     * Inherits from Requirements::RequirementCheck, providing
		     * built-in subject, assumptions, and constraints. */
		subject target;
		attribute isImplemented : ScalarValues::Boolean;
	}

	// ─── Allocation Definition (bind a requirement to a component) ───

	allocation def Mitigation {
		doc /* Formally binds a SecurityRequirement (mitigation) to the
		     * Component it protects. Inherits from Allocations::Allocation,
		     * a binary connection with source and target ends. */
		end source;
		end target;
	}
}
