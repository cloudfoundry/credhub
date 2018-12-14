package org.cloudfoundry.credhub.config;

@SuppressWarnings("PMD.SingularField")
public enum ProviderType {

  INTERNAL("internal"),
  HSM("hsm"),
  KMS_PLUGIN("kms-plugin");

  @SuppressWarnings("unused")
  private final String label;

  ProviderType(final String label) {
    this.label = label;
  }
}
