package org.cloudfoundry.credhub.config;

public enum ProviderType {

  INTERNAL("internal"),
  HSM("hsm"),
  KMS_PLUGIN("kms-plugin");

  private String label;

  ProviderType(String label) {
    this.label = label;
  }
}
