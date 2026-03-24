package BasicWebAppArchitecture {
	doc /* Threat model for the Azure Basic Web App architecture.
	     * Reference: https://learn.microsoft.com/en-us/azure/architecture/web-apps/app-service/architectures/basic-web-app
	     *
	     * Components: User, App Service (with Easy Auth), Microsoft Entra ID,
	     * Azure SQL Database, Application Insights, Azure Monitor.
	     *
	     * Threats are modelled as concern defs (stakeholder worries).
	     * Mitigations are modelled as requirement defs (security controls). */

	private import ThreatModelToolbox::*;

	// ─── Architecture ───

	part basicWebApp 
    {
		doc /* The complete basic web app architecture with trust boundaries, components, and threats. */

		// ── Trust Boundaries (components nested inside their boundary) ──

		part internetBoundary : TrustBoundary {
			:>> description = "The public internet — untrusted zone.";

			part externalAttacker : ThreatActor {
				:>> description = "An unauthenticated attacker on the public internet.";
				:>> motivation = ActorMotivationKind::financial;
				:>> capability = ActorCapabilityKind::opportunistic;
			}

			part maliciousInsider : ThreatActor {
				:>> description = "An authenticated user or operator who abuses their access.";
				:>> motivation = ActorMotivationKind::financial;
				:>> capability = ActorCapabilityKind::insider;
			}
		}

		part azurePlatformBoundary : TrustBoundary {
			:>> description = "The Azure platform boundary. All components share the Azure trust plane.";

			part appService : WebApplication {
				:>> description = "Azure App Service hosting the web application code.";
				:>> isPubliclyAccessible = true;
				:>> authentication = AuthenticationKind::oauthToken;
				:>> encryption = EncryptionKind::inTransit;
			}

			part entraId : IdentityProvider {
				:>> description = "Microsoft Entra ID providing authentication via Easy Auth.";
				:>> isPubliclyAccessible = true;
				:>> authentication = AuthenticationKind::oauthToken;
				:>> encryption = EncryptionKind::both;
			}

			part sqlDatabase : DataStore {
				:>> description = "Azure SQL Database storing application data.";
				:>> isPubliclyAccessible = true;
				:>> authentication = AuthenticationKind::apiKey;
				:>> encryption = EncryptionKind::both;
				:>> dataClassification = DataClassificationKind::confidential;
			}

			part appInsights : MonitoringService {
				:>> description = "Application Insights collecting telemetry from App Service and SQL Database.";
				:>> isPubliclyAccessible = false;
				:>> authentication = AuthenticationKind::apiKey;
				:>> encryption = EncryptionKind::both;
			}

			part azureMonitor : MonitoringService {
				:>> description = "Azure Monitor aggregating logs and metrics.";
				:>> isPubliclyAccessible = false;
				:>> authentication = AuthenticationKind::managedIdentity;
				:>> encryption = EncryptionKind::both;
			}
		}
    }

	// ── Components ──

    occurrence def SuccessfulHttpRequest {
        doc /* A successful HTTP request from the user to the web application. */

		succession flow userToApp of HttpRequest
			from basicWebApp.internetBoundary.externalAttacker
			to basicWebApp.azurePlatformBoundary.appService {
			doc /* HTTPS request from the user's browser to App Service. */
			@StrideTag {
				category = StrideCategoryKind::spoofing;
				severity = SeverityKind::high;
				likelihood = LikelihoodKind::likely;
			}
		}

		then succession flow appToEntra of HttpRequest
			from basicWebApp.azurePlatformBoundary.appService 
			to basicWebApp.azurePlatformBoundary.entraId {
			doc /* Easy Auth redirects unauthenticated requests to Entra ID for OAuth2 authentication. */
		}

		then succession flow appToSql of DatabaseQuery
			from basicWebApp.azurePlatformBoundary.appService
			to basicWebApp.azurePlatformBoundary.sqlDatabase {
			doc /* App Service queries SQL Database using a connection string stored in app settings. */
			@StrideTag {
				category = StrideCategoryKind::tampering;
				severity = SeverityKind::critical;
				likelihood = LikelihoodKind::possible;
			}
		}

		then succession flow sqlToApp of DatabaseResult
			from basicWebApp.azurePlatformBoundary.sqlDatabase 
			to basicWebApp.azurePlatformBoundary.appService {
			doc /* SQL Database returns result sets to App Service. */
			@StrideTag {
				category = StrideCategoryKind::informationDisclosure;
				severity = SeverityKind::high;
				likelihood = LikelihoodKind::likely;
			}
		}

		then succession flow appToInsights of TelemetryPayload
			from basicWebApp.azurePlatformBoundary.appService 
			to basicWebApp.azurePlatformBoundary.appInsights {
			doc /* App Service emits request traces and dependency telemetry to Application Insights. */
		}
    }

	// ── Threats ──

	concern spoofingNoWaf : Threat {
		doc /* Without a WAF, attackers can send crafted requests directly to
		     * App Service, potentially spoofing legitimate clients. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> strideCategory = StrideCategoryKind::spoofing;
		:>> severity = SeverityKind::high;
		:>> likelihood = LikelihoodKind::likely;
		:>> targetDescription = "App Service public endpoint";
	}

	concern sqlInjection : Threat {
		doc /* Application code may be vulnerable to SQL injection if queries
		     * are not parameterised. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> strideCategory = StrideCategoryKind::tampering;
		:>> severity = SeverityKind::critical;
		:>> likelihood = LikelihoodKind::possible;
		:>> targetDescription = "App Service to SQL Database data flow";
	}

	concern secretsInAppSettings : Threat {
		doc /* Connection strings stored in App Settings could be exposed
		     * through misconfiguration, Kudu, or memory dumps. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> strideCategory = StrideCategoryKind::informationDisclosure;
		:>> severity = SeverityKind::high;
		:>> likelihood = LikelihoodKind::possible;
		:>> targetDescription = "App Service configuration";
	}

	concern publicSqlEndpoint : Threat {
		doc /* SQL Database is reachable over the public internet, broadening
		     * the attack surface. */
		subject :>> target = basicWebApp.azurePlatformBoundary.sqlDatabase;
		:>> strideCategory = StrideCategoryKind::informationDisclosure;
		:>> severity = SeverityKind::high;
		:>> likelihood = LikelihoodKind::likely;
		:>> targetDescription = "Azure SQL Database public endpoint";
	}

	concern noRateLimiting : Threat {
		doc /* Without a gateway or WAF, App Service is vulnerable to volumetric
		     * DDoS or application-layer denial of service. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> strideCategory = StrideCategoryKind::denialOfService;
		:>> severity = SeverityKind::medium;
		:>> likelihood = LikelihoodKind::likely;
		:>> targetDescription = "App Service public endpoint";
	}

	concern insufficientLogging : Threat {
		doc /* Without Defender for App Service, security events may not be
		     * detected or alerted on. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appInsights;
		:>> strideCategory = StrideCategoryKind::repudiation;
		:>> severity = SeverityKind::medium;
		:>> likelihood = LikelihoodKind::possible;
		:>> targetDescription = "Monitoring and alerting";
	}

	concern kuduExposure : Threat {
		doc /* Kudu SCM endpoint and remote debugging are enabled, giving
		     * attackers potential control-plane access. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> strideCategory = StrideCategoryKind::elevationOfPrivilege;
		:>> severity = SeverityKind::high;
		:>> likelihood = LikelihoodKind::possible;
		:>> targetDescription = "App Service control plane (Kudu/SCM)";
	}

	// ── Mitigations ──

	requirement enableWaf : SecurityRequirement {
		doc /* Deploy Azure Application Gateway with Web Application Firewall
		     * in front of App Service. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

	requirement useParameterisedQueries : SecurityRequirement {
		doc /* Use parameterised queries or an ORM to prevent SQL injection. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = true;
	}

	requirement useManagedIdentity : SecurityRequirement {
		doc /* Replace connection string credentials with managed identity
		     * authentication to SQL. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

	requirement useKeyVault : SecurityRequirement {
		doc /* Store secrets in Azure Key Vault and use Key Vault references
		     * in App Settings. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

	requirement usePrivateLink : SecurityRequirement {
		doc /* Enable Azure Private Link to remove the SQL Database public endpoint. */
		subject :>> target = basicWebApp.azurePlatformBoundary.sqlDatabase;
		:>> isImplemented = false;
	}

	requirement firewallRules : SecurityRequirement {
		doc /* Configure SQL firewall rules to allow only App Service outbound IPs. */
		subject :>> target = basicWebApp.azurePlatformBoundary.sqlDatabase;
		:>> isImplemented = false;
	}

	requirement enableDdosProtection : SecurityRequirement {
		doc /* Deploy Azure DDoS Protection and Application Gateway with rate limiting. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

	requirement enableDefender : SecurityRequirement {
		doc /* Enable Microsoft Defender for App Service and configure security alerts. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

	requirement enableDiagnosticLogs : SecurityRequirement {
		doc /* Enable full diagnostic logging and ship logs to Log Analytics. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appInsights;
		:>> isImplemented = false;
	}

	requirement disableRemoteDebug : SecurityRequirement {
		doc /* Disable remote debugging and restrict SCM access in production. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

	requirement disableLocalAuth : SecurityRequirement {
		doc /* Disable local FTP and SCM authentication methods. */
		subject :>> target = basicWebApp.azurePlatformBoundary.appService;
		:>> isImplemented = false;
	}

    // ── Allocations of mitigations to components ──

	allocation mitigation1 : Mitigation allocate BasicWebAppArchitecture::enableWaf to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation2 : Mitigation allocate BasicWebAppArchitecture::useParameterisedQueries to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation3 : Mitigation allocate BasicWebAppArchitecture::useManagedIdentity to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation4 : Mitigation allocate BasicWebAppArchitecture::useKeyVault to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation5 : Mitigation allocate BasicWebAppArchitecture::usePrivateLink to basicWebApp.azurePlatformBoundary.sqlDatabase;
	allocation mitigation6 : Mitigation allocate BasicWebAppArchitecture::firewallRules to basicWebApp.azurePlatformBoundary.sqlDatabase;
	allocation mitigation7 : Mitigation allocate BasicWebAppArchitecture::enableDdosProtection to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation8 : Mitigation allocate BasicWebAppArchitecture::enableDefender to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation9 : Mitigation allocate BasicWebAppArchitecture::enableDiagnosticLogs to basicWebApp.azurePlatformBoundary.appInsights;
	allocation mitigation10 : Mitigation allocate BasicWebAppArchitecture::disableRemoteDebug to basicWebApp.azurePlatformBoundary.appService;
	allocation mitigation11 : Mitigation allocate BasicWebAppArchitecture::disableLocalAuth to basicWebApp.azurePlatformBoundary.appService;
	

}
