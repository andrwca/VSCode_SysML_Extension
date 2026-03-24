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

	// ─── Metadata Definition (annotate any element) ───

	metadata def StrideTag {
		doc /* Annotate any element (port, interface, flow, component) with a
		     * STRIDE threat classification. Apply with @StrideTag { ... }. */
		attribute category : StrideCategoryKind;
		attribute severity : SeverityKind;
		attribute likelihood : LikelihoodKind;
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

	// ─── Port Definitions (connection points) ───

	port def HttpEndpoint {
		doc /* A port that accepts and returns HTTP traffic.
		     * Use ~HttpEndpoint for the client (conjugate) side. */
		in item requests : HttpRequest;
		out item responses : HttpResponse;
	}

	port def AuthProviderPort {
		doc /* A port on an identity provider that issues tokens.
		     * Use ~AuthProviderPort for the requester (conjugate) side. */
		in item authRequests : HttpRequest;
		out item tokens : AuthToken;
	}

	port def DatabaseServerPort {
		doc /* A port on a data store that accepts queries.
		     * Use ~DatabaseServerPort for the client (conjugate) side. */
		in item queries : DatabaseQuery;
		out item results : DatabaseResult;
	}

	port def TelemetrySinkPort {
		doc /* A port that receives telemetry data.
		     * Use ~TelemetrySinkPort for the source (conjugate) side. */
		in item telemetry : TelemetryPayload;
	}

	port def SecretStorePort {
		doc /* A port on a secret store that serves credentials.
		     * Use ~SecretStorePort for the accessor (conjugate) side. */
		in item secretRequests : HttpRequest;
		out item secrets : Credential;
	}

	// ─── Component Definitions (architectural building blocks) ───

	abstract part def Component {
		doc /* Base definition for any processing element in the architecture. */
		attribute description : ScalarValues::String;
		attribute isPubliclyAccessible : ScalarValues::Boolean;
		attribute authentication : AuthenticationKind;
		attribute encryption : EncryptionKind;
		port telemetryOut : ~TelemetrySinkPort;
	}

	part def WebApplication :> Component {
		doc /* A web application or API hosted on a compute platform. */
		port httpIn : HttpEndpoint;
		port authOut : ~AuthProviderPort;
		port dbOut : ~DatabaseServerPort;
		port secretsOut : ~SecretStorePort;
	}

	part def IdentityProvider :> Component {
		doc /* An identity and access management service (e.g. Microsoft Entra ID). */
		port authIn : AuthProviderPort;
	}

	part def DataStore :> Component {
		doc /* A persistent data store (SQL database, NoSQL, blob storage, etc.). */
		attribute dataClassification : DataClassificationKind;
		port dbIn : DatabaseServerPort;
	}

	part def SecretStore :> Component {
		doc /* A dedicated secret management service (e.g. Azure Key Vault). */
		port secretsIn : SecretStorePort;
	}

	part def MonitoringService :> Component {
		doc /* A monitoring, logging, or telemetry aggregation service. */
		port telemetryIn : TelemetrySinkPort;
	}

	part def Gateway :> Component {
		doc /* A network gateway, load balancer, or WAF. */
		port externalIn : HttpEndpoint;
		port internalOut : ~HttpEndpoint;
	}

	part def ExternalSystem :> Component {
		doc /* An external system or third-party service. */
		port httpIn : HttpEndpoint;
	}

	// ─── Threat Actor ───

	part def ThreatActor {
		doc /* An entity that poses a threat to the system. */
		attribute description : ScalarValues::String;
		attribute motivation : ActorMotivationKind;
		attribute capability : ActorCapabilityKind;
		port clientPort : ~HttpEndpoint;
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
