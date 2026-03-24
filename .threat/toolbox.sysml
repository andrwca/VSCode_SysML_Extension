// @toolbox-category: _library
// @toolbox-label: Toolbox Re-export
// @toolbox-icon: 📦
// @toolbox-description: Meta-package that re-exports all threat modelling definitions. Use 'private import ThreatModelToolbox::*;' in your models.
// @toolbox-order: 99
// @toolbox-hidden: true

package ThreatModelToolbox {
  doc
  /* Re-exports all threat modelling definitions as a single import.
   * Use: private import ThreatModelToolbox::*;
   */

  public import ThreatEnumerations::*;
  public import ThreatMetadata::*;
  public import ThreatItems::*;
  public import ThreatPorts::*;
  public import ThreatComponents::*;
  public import ThreatActors::*;
  public import ThreatDefinitions::*;
}
