package org.cloudfoundry.credhub.config;

public enum ProviderType {

  INTERNAL ("internal"),
  HSM ("hsm");

  private String label;

  ProviderType(String label) {
    this.label = label;
  }
}
