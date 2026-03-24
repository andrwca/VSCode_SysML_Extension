// @toolbox-category: actors
// @toolbox-label: Actors & Boundaries
// @toolbox-icon: 👤
// @toolbox-description: Threat actors and trust boundaries — define who threatens the system and where trust changes.
// @toolbox-order: 2

package ThreatActors {
  doc
  /* Threat actors and trust boundary definitions. */

  private import ThreatEnumerations::*;
  private import ThreatPorts::*;
  private import ThreatComponents::*;

  // @toolbox-icon: 👤
  part def ThreatActor {
    doc
    /* An entity that poses a threat to the system. */
    attribute description : ScalarValues::String;
    attribute motivation : ActorMotivationKind;
    attribute capability : ActorCapabilityKind;
    port clientPort : ~HttpEndpoint;
  }

  // @toolbox-icon: 🔲
  part def TrustBoundary {
    doc
    /* A logical boundary separating zones of differing trust levels. */
    attribute description : ScalarValues::String;
    part components : Component [0..*];
  }
}
