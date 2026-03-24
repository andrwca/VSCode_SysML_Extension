// @toolbox-category: threats
// @toolbox-label: Threats & Mitigations
// @toolbox-icon: ⚠️
// @toolbox-description: Threat concerns, security requirements, and mitigation allocations for risk management.
// @toolbox-order: 3

package ThreatDefinitions {
  doc
  /* Threat concerns, security requirements, and mitigation allocations. */

  private import ThreatEnumerations::*;

  // @toolbox-icon: ⚠️
  concern def Threat {
    doc
    /* A threat identified against a component or data flow. */
    subject target;
    attribute strideCategory : StrideCategoryKind;
    attribute severity : SeverityKind;
    attribute likelihood : LikelihoodKind;
    attribute targetDescription : ScalarValues::String;
  }

  // @toolbox-icon: ✅
  requirement def SecurityRequirement {
    doc
    /* A security control or countermeasure that addresses a threat. */
    subject target;
    attribute isImplemented : ScalarValues::Boolean;
  }

  // @toolbox-icon: 🔧
  allocation def Mitigation {
    doc
    /* Binds a SecurityRequirement to the Component it protects. */
    end source;
    end target;
  }
}
