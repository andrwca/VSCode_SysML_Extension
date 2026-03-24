// @toolbox-category: _library
// @toolbox-label: Enumerations
// @toolbox-icon: 📋
// @toolbox-description: STRIDE, severity, likelihood, and other classification enumerations. Not directly draggable — used by other definitions.
// @toolbox-order: 99
// @toolbox-hidden: true

package ThreatEnumerations {
  doc
  /* STRIDE threat classification and risk assessment enumerations. */

  enum def StrideCategoryKind {
    enum spoofing;
    enum tampering;
    enum repudiation;
    enum informationDisclosure;
    enum denialOfService;
    enum elevationOfPrivilege;
  }

  enum def SeverityKind {
    enum critical;
    enum high;
    enum medium;
    enum low;
    enum informational;
  }

  enum def LikelihoodKind {
    enum almostCertain;
    enum likely;
    enum possible;
    enum unlikely;
    enum rare;
  }

  enum def AuthenticationKind {
    enum none;
    enum apiKey;
    enum certificate;
    enum managedIdentity;
    enum oauthToken;
    enum saml;
  }

  enum def DataClassificationKind {
    enum public_;
    enum internal_;
    enum confidential;
    enum restricted;
  }

  enum def EncryptionKind {
    enum none;
    enum inTransit;
    enum atRest;
    enum both;
  }

  enum def ActorMotivationKind {
    enum financial;
    enum espionage;
    enum disruption;
    enum ideological;
    enum accidental;
  }

  enum def ActorCapabilityKind {
    enum nationState;
    enum organised;
    enum skilled;
    enum opportunistic;
    enum insider;
  }
}
