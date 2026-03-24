// @toolbox-category: _library
// @toolbox-label: Ports
// @toolbox-icon: 🔌
// @toolbox-description: Port definitions (HTTP endpoints, database ports, telemetry sinks). Not directly draggable — used as connection points on components.
// @toolbox-order: 99
// @toolbox-hidden: true

package ThreatPorts {
  doc
  /* Port definitions — typed interaction points on components. */

  private import ThreatItems::*;

  port def HttpEndpoint {
    doc
    /* A port that accepts and returns HTTP traffic. */
    in item requests : HttpRequest;
    out item responses : HttpResponse;
  }

  port def AuthProviderPort {
    doc
    /* A port on an identity provider that issues tokens. */
    in item authRequests : HttpRequest;
    out item tokens : AuthToken;
  }

  port def DatabaseServerPort {
    doc
    /* A port on a data store that accepts queries. */
    in item queries : DatabaseQuery;
    out item results : DatabaseResult;
  }

  port def TelemetrySinkPort {
    doc
    /* A port that receives telemetry data. */
    in item telemetry : TelemetryPayload;
  }

  port def SecretStorePort {
    doc
    /* A port on a secret store that serves credentials. */
    in item secretRequests : HttpRequest;
    out item secrets : Credential;
  }
}
