// @toolbox-category: components
// @toolbox-label: Components
// @toolbox-icon: 📦
// @toolbox-description: Architectural building blocks — drag onto the canvas to add infrastructure components.
// @toolbox-order: 1

package ThreatComponents {
  doc
  /* Architectural building-block definitions for threat models. */

  private import ThreatEnumerations::*;
  private import ThreatPorts::*;

  abstract part def Component {
    doc
    /* Base definition for any processing element in the architecture. */
    attribute description : ScalarValues::String;
    attribute isPubliclyAccessible : ScalarValues::Boolean;
    attribute authentication : AuthenticationKind;
    attribute encryption : EncryptionKind;
    port telemetryOut : ~TelemetrySinkPort;
  }

  // @toolbox-icon: 🌐
  part def WebApplication :> Component {
    doc
    /* A web application or API hosted on a compute platform. */
    port httpIn : HttpEndpoint;
    port authOut : ~AuthProviderPort;
    port dbOut : ~DatabaseServerPort;
    port secretsOut : ~SecretStorePort;
  }

  // @toolbox-icon: 🔑
  part def IdentityProvider :> Component {
    doc
    /* An identity and access management service. */
    port authIn : AuthProviderPort;
  }

  // @toolbox-icon: 🗄️
  part def DataStore :> Component {
    doc
    /* A persistent data store (SQL, NoSQL, blob, etc.). */
    attribute dataClassification : DataClassificationKind;
    port dbIn : DatabaseServerPort;
  }

  // @toolbox-icon: 🔒
  part def SecretStore :> Component {
    doc
    /* A dedicated secret management service. */
    port secretsIn : SecretStorePort;
  }

  // @toolbox-icon: 📊
  part def MonitoringService :> Component {
    doc
    /* A monitoring, logging, or telemetry aggregation service. */
    port telemetryIn : TelemetrySinkPort;
  }

  // @toolbox-icon: 🛡️
  part def Gateway :> Component {
    doc
    /* A network gateway, load balancer, or WAF. */
    port externalIn : HttpEndpoint;
    port internalOut : ~HttpEndpoint;
  }

  // @toolbox-icon: 🔗
  part def ExternalSystem :> Component {
    doc
    /* An external system or third-party service. */
    port httpIn : HttpEndpoint;
  }
}
