// @toolbox-category: _library
// @toolbox-label: Data Items
// @toolbox-icon: 📨
// @toolbox-description: Data-in-motion definitions (HTTP requests, tokens, queries). Not directly draggable — used as port item types.
// @toolbox-order: 99
// @toolbox-hidden: true

package ThreatItems {
  doc
  /* Data-in-motion definitions — things that flow between components. */

  private import ThreatEnumerations::*;

  item def HttpRequest {
    doc
    /* An HTTP/HTTPS request flowing between components. */
    attribute method : ScalarValues::String;
    attribute isEncrypted : ScalarValues::Boolean;
  }

  item def HttpResponse {
    doc
    /* An HTTP/HTTPS response returned from a component. */
    attribute statusCode : ScalarValues::Integer;
    attribute isEncrypted : ScalarValues::Boolean;
  }

  item def AuthToken {
    doc
    /* An authentication or authorisation token. */
    attribute tokenType : AuthenticationKind;
  }

  item def DatabaseQuery {
    doc
    /* A query sent to a data store. */
    attribute isParameterised : ScalarValues::Boolean;
  }

  item def DatabaseResult {
    doc
    /* A result set returned from a data store. */
    attribute dataClassification : DataClassificationKind;
  }

  item def TelemetryPayload {
    doc
    /* Telemetry, logs, or metrics emitted by a component. */
  }

  item def Credential {
    doc
    /* A secret, connection string, key, or certificate. */
    attribute classification : DataClassificationKind;
  }
}
