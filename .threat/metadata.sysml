// @toolbox-category: _library
// @toolbox-label: Metadata
// @toolbox-icon: 🏷️
// @toolbox-description: STRIDE annotation tags for marking any model element. Not directly draggable — apply via @StrideTag.
// @toolbox-order: 99
// @toolbox-hidden: true

package ThreatMetadata {
  doc
  /* STRIDE annotation metadata for tagging any model element. */

  private import ThreatEnumerations::*;

  metadata def StrideTag {
    doc
    /* Annotate any element with a STRIDE threat classification.
     * Apply with @StrideTag { ... }.
     */
    attribute category : StrideCategoryKind;
    attribute severity : SeverityKind;
    attribute likelihood : LikelihoodKind;
  }
}
