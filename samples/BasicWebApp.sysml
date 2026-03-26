package BasicWebApp {
	doc
	/* Threat model for the Azure Basic Web App architecture.
	 * Reference: https://learn.microsoft.com/en-us/azure/architecture/web-apps/app-service/architectures/basic-web-app
	 *
	 * Components: User, App Service (with Easy Auth), Microsoft Entra ID,
	 * Azure SQL Database, Application Insights, Azure Monitor.
	 *
	 * Threats are modelled as concern defs (stakeholder worries).
	 * Mitigations are modelled as requirement defs (security controls).
	 */

	private import ThreatModelToolbox::*;

	// ─── Architecture ───

	part architecture {
		doc
		/* The complete basic web app architecture with trust boundaries, components, and threats. */

		// ── Trust Boundaries (components nested inside their boundary) ──

		part internetBoundary : TrustBoundary {
			:>> description = "The public internet — untrusted zone.";

			part endUser : Actor {
				:>> description = "An unauthenticated user on the public internet.";
			}
		}

		part azurePlatformBoundary : TrustBoundary {
			:>> description = "The Azure platform boundary. All components share the Azure trust plane.";

			part appService : Component.AzureAppService {
				:>> description = "Azure App Service hosting the web application code.";
				:>> isPubliclyAccessible = true;
				:>> authentication = AuthenticationKind::oauthToken;
				:>> encryption = EncryptionKind::inTransit;
			}

			part entraId : Component.AzureEntraID {
				:>> description = "Microsoft Entra ID providing authentication via Easy Auth.";
				:>> isPubliclyAccessible = true;
				:>> authentication = AuthenticationKind::oauthToken;
				:>> encryption = EncryptionKind::both;
			}

			part sqlDatabase : Component.AzureSQLDatabase {
				:>> description = "Azure SQL Database storing application data.";
				:>> isPubliclyAccessible = true;
				:>> authentication = AuthenticationKind::apiKey;
				:>> encryption = EncryptionKind::both;
				:>> dataClassification = DataClassificationKind::confidential;
			}

			part appInsights : Component.AzureApplicationInsights {
				:>> description =
					"Application Insights collecting telemetry from App Service and SQL Database.";
				:>> isPubliclyAccessible = false;
				:>> authentication = AuthenticationKind::apiKey;
				:>> encryption = EncryptionKind::both;
			}
		}
	}

	// ── Data flows ──

	occurrence successfulHttpRequest {
		doc
		/* A successful HTTP request from the user to the web application. */

		succession flow userToApp of HttpRequest
			from architecture.internetBoundary.endUser
			to architecture.azurePlatformBoundary.appService {
			doc
			/* HTTPS request from the user's browser to App Service. */
		}

		then succession flow appToEntra of HttpRequest
			from architecture.azurePlatformBoundary.appService
			to architecture.azurePlatformBoundary.entraId {
			doc
			/* Easy Auth redirects unauthenticated requests to Entra ID for OAuth2 authentication. */
		}

		then succession flow appToSql of DatabaseQuery
			from architecture.azurePlatformBoundary.appService
			to architecture.azurePlatformBoundary.sqlDatabase {
			doc
			/* App Service queries SQL Database using a connection string stored in app settings. */
		}

		then succession flow sqlToApp of DatabaseResult
			from architecture.azurePlatformBoundary.sqlDatabase
			to architecture.azurePlatformBoundary.appService {
			doc
			/* SQL Database returns result sets to App Service. */
		}

		then succession flow appToInsights of TelemetryPayload
			from architecture.azurePlatformBoundary.appService
			to architecture.azurePlatformBoundary.appInsights {
			doc
			/* App Service emits request traces and dependency telemetry to Application Insights. */
		}

		then succession flow appToUser of HttpResponse
			from architecture.azurePlatformBoundary.appService
			to architecture.internetBoundary.endUser {
			doc
			/* HTTPS response from App Service back to the user's browser. */
		}
	}

	  // ── Threats ──

    part threats {

        concern brokenAuthentication : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-01: Broken or non-existent authentication on App Service could allow
             * attackers to bypass Easy Auth and access the web application or its backend
             * services without valid credentials. */
            subject :>> target = architecture.azurePlatformBoundary.appService;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::spoofing;
            :>> severity = ThreatModelToolbox::SeverityKind::critical;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::likely;
            :>> targetDescription = "Azure App Service hosting the web application";
        }

        concern publicServiceExposure : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-02: App Service is publicly accessible on the internet, presenting a
             * large attack surface that increases the probability of compromise through
             * exploitation of vulnerabilities or misconfigurations. */
            subject :>> target = architecture.azurePlatformBoundary.appService;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::spoofing;
            :>> severity = ThreatModelToolbox::SeverityKind::high;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::likely;
            :>> targetDescription = "Publicly exposed Azure App Service";
        }

        concern distributedDenialOfService : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-03: The internet-facing App Service is susceptible to DDoS attacks that
             * could exhaust resources and render the web application unavailable to
             * legitimate users. */
            subject :>> target = architecture.azurePlatformBoundary.appService;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::denialOfService;
            :>> severity = ThreatModelToolbox::SeverityKind::high;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::likely;
            :>> targetDescription = "Internet-facing Azure App Service";
        }

        concern insufficientLogging : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-04: Insufficient logging and monitoring via Application Insights could
             * allow attackers to operate undetected, making incident response slower and
             * forensic analysis incomplete. */
            subject :>> target = architecture.azurePlatformBoundary.appInsights;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::repudiation;
            :>> severity = ThreatModelToolbox::SeverityKind::high;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::likely;
            :>> targetDescription = "Application Insights telemetry and monitoring";
        }

        concern manInTheMiddle : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-05: Traffic between the end user and App Service could be intercepted
             * via man-in-the-middle attacks if TLS is misconfigured, downgraded, or not
             * enforced, exposing credentials and session tokens. */
            subject :>> target = successfulHttpRequest.userToApp;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::informationDisclosure;
            :>> severity = ThreatModelToolbox::SeverityKind::high;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::possible;
            :>> targetDescription = "HTTPS request from user browser to App Service";
        }

        concern secretsLeaking : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-06: Secrets such as the SQL Database connection string stored in App
             * Service configuration could leak into logs, source control, or error messages,
             * giving adversaries direct access to backend resources. */
            subject :>> target = architecture.azurePlatformBoundary.appService;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::informationDisclosure;
            :>> severity = ThreatModelToolbox::SeverityKind::critical;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::likely;
            :>> targetDescription = "App Service holding connection strings and secrets";
        }

        concern authorizationSubversion : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-09: Authorization controls in Entra ID could be subverted, allowing an
             * authenticated user to escalate privileges or access resources beyond their
             * intended scope within the application. */
            subject :>> target = architecture.azurePlatformBoundary.entraId;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::elevationOfPrivilege;
            :>> severity = ThreatModelToolbox::SeverityKind::critical;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::possible;
            :>> targetDescription = "Microsoft Entra ID identity and access management";
        }

        concern unencryptedInternalTraffic : ThreatModelToolbox::Threat {
            doc
            /* T-GEN-10: Database queries between App Service and SQL Database may traverse
             * the Azure network unencrypted, potentially exposing confidential data and
             * causing compliance violations. */
            subject :>> target = successfulHttpRequest.appToSql;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::informationDisclosure;
            :>> severity = ThreatModelToolbox::SeverityKind::medium;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::possible;
            :>> targetDescription = "Database query traffic from App Service to SQL Database";
        }

        concern headerExploitation : ThreatModelToolbox::Threat {
            doc
            /* T-APP-02: Missing or misconfigured security headers (HSTS, CSP,
             * X-Content-Type-Options) on App Service responses could allow attackers to
             * perform clickjacking, MIME-sniffing, or cross-site scripting attacks. */
            subject :>> target = architecture.azurePlatformBoundary.appService;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::tampering;
            :>> severity = ThreatModelToolbox::SeverityKind::high;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::likely;
            :>> targetDescription = "App Service HTTP responses missing security headers";
        }

        concern multitenantDataBreach : ThreatModelToolbox::Threat {
            doc
            /* T-APP-01: In a multi-tenant scenario, a compromised tenant could exploit
             * SQL Database vulnerabilities to access, modify, or disrupt another tenant's
             * data, leading to cross-tenant data leaks. */
            subject :>> target = architecture.azurePlatformBoundary.sqlDatabase;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::informationDisclosure;
            :>> severity = ThreatModelToolbox::SeverityKind::critical;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::possible;
            :>> targetDescription = "Azure SQL Database in multi-tenant configuration";
        }

        concern directDataStoreAttack : ThreatModelToolbox::Threat {
            doc
            /* T-DATA-02: Attackers may target the SQL Database directly rather than going
             * through the application layer, enabling large-scale data exfiltration of
             * confidential application data. */
            subject :>> target = architecture.azurePlatformBoundary.sqlDatabase;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::informationDisclosure;
            :>> severity = ThreatModelToolbox::SeverityKind::critical;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::possible;
            :>> targetDescription = "Azure SQL Database storing confidential data";
        }

        concern dataRetentionNonCompliance : ThreatModelToolbox::Threat {
            doc
            /* T-DATA-01: The application may not support deletion of user profiles and
             * associated data from SQL Database, potentially violating GDPR or other
             * data protection regulations. */
            subject :>> target = architecture.azurePlatformBoundary.sqlDatabase;
            :>> strideCategory = ThreatModelToolbox::StrideCategoryKind::repudiation;
            :>> severity = ThreatModelToolbox::SeverityKind::medium;
            :>> likelihood = ThreatModelToolbox::LikelihoodKind::possible;
            :>> targetDescription = "Azure SQL Database user data retention";
        }

    }

	  // ── Mitigations ──

    part mitigations {

        requirement enforceAppServiceAuth : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Ensure all App Service incoming requests are authenticated via Entra ID
             * Easy Auth. Use Managed Identities for service-to-service calls. */
            subject :>> target = threats.brokenAuthentication;
            :>> isImplemented = false;
        }

        requirement usePrivateEndpoints : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Restrict App Service access with Azure Private Endpoints and NSGs to
             * reduce the public attack surface. Enable Azure Defender. */
            subject :>> target = threats.publicServiceExposure;
            :>> isImplemented = false;
        }

        requirement enableDdosProtection : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Enable Azure DDoS Protection Standard plan for the App Service and
             * associated resources to mitigate volumetric and protocol attacks. */
            subject :>> target = threats.distributedDenialOfService;
            :>> isImplemented = false;
        }

        requirement implementComprehensiveMonitoring : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Configure Application Insights to log all security-relevant events
             * (login/logout, auth failures, privilege changes). Integrate with
             * Azure Monitor and consider Microsoft Sentinel as SIEM. */
            subject :>> target = threats.insufficientLogging;
            :>> isImplemented = false;
        }

        requirement enforceHsts : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Enforce HTTPS via HSTS with adequate max-age. Use TLS 1.2+ with
             * ECDHE-based cipher suites and NIST curves. Disable TLS compression. */
            subject :>> target = threats.manInTheMiddle;
            :>> isImplemented = false;
        }

        requirement storeSecretsInKeyVault : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Move all secrets (SQL connection strings, API keys) to Azure Key Vault.
             * Use Managed Identity for App Service to access Key Vault. Set expiration
             * dates and implement rotation strategy. */
            subject :>> target = threats.secretsLeaking;
            :>> isImplemented = false;
        }

        requirement enforceRbacLeastPrivilege : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Use Azure RBAC to grant least-privilege access. Configure Entra ID
             * Conditional Access policies and enable PIM for administrative roles. */
            subject :>> target = threats.authorizationSubversion;
            :>> isImplemented = false;
        }

        requirement encryptDatabaseTraffic : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Enable TLS encryption for connections between App Service and SQL Database.
             * Use the "Encrypt=True" and "TrustServerCertificate=False" connection string
             * options. */
            subject :>> target = threats.unencryptedInternalTraffic;
            :>> isImplemented = false;
        }

        requirement configureSecurityHeaders : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Configure HSTS, Content-Security-Policy, X-Content-Type-Options (nosniff),
             * and X-Frame-Options headers on all App Service responses. Implement
             * monitoring for header policy violations. */
            subject :>> target = threats.headerExploitation;
            :>> isImplemented = false;
        }

        requirement implementTenantIsolation : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Apply Row-Level Security (RLS) and data masking in SQL Database.
             * Validate tenant-specific tokens and claims at the API layer. Implement
             * per-tenant resource throttling. */
            subject :>> target = threats.multitenantDataBreach;
            :>> isImplemented = false;
        }

        requirement hardenSqlAccess : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Disable public network access to SQL Database. Use Private Endpoints.
             * Enable TDE and ensure encryption at rest with AES-256. Enable Azure
             * Defender for SQL. */
            subject :>> target = threats.directDataStoreAttack;
            :>> isImplemented = false;
        }

        requirement implementDataDeletionCapability : ThreatModelToolbox::SecurityRequirement {
            doc
            /* Implement user profile and data deletion functionality to comply with
             * GDPR right-to-erasure requirements. Ensure deletion covers all associated
             * data across all datastores. */
            subject :>> target = threats.dataRetentionNonCompliance;
            :>> isImplemented = false;
        }

    }
}