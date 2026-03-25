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

    }

	  // ── Mitigations ──

    part mitigations {

    }
}


