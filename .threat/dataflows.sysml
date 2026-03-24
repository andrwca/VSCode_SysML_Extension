// @toolbox-category: dataflows
// @toolbox-label: Data Flows
// @toolbox-icon: 🔀
// @toolbox-description: Succession flows and data-in-motion sequences between components.
// @toolbox-order: 4

package ThreatDataFlows {
  doc
  /* Data flow definitions — succession flows that carry data items between components.
   * Drag a flow type onto the canvas, then connect source → target.
   */

  private import ThreatItems::*;
  private import ThreatMetadata::*;

  // @toolbox-icon: 🌐
  occurrence def HttpFlow {
    doc
    /* An HTTP/HTTPS request–response flow between two components. */
  }

  // @toolbox-icon: 🔑
  occurrence def AuthFlow {
    doc
    /* An authentication/authorisation flow (OAuth redirect, token exchange). */
  }

  // @toolbox-icon: 🗄️
  occurrence def DatabaseFlow {
    doc
    /* A database query and result flow. */
  }

  // @toolbox-icon: 📊
  occurrence def TelemetryFlow {
    doc
    /* A telemetry, logging, or monitoring data flow. */
  }

  // @toolbox-icon: 🔒
  occurrence def SecretFlow {
    doc
    /* A flow of secrets, keys, or credentials between components. */
  }

  // @toolbox-icon: 🔗
  occurrence def GenericFlow {
    doc
    /* A generic data flow between two components. */
  }
}
