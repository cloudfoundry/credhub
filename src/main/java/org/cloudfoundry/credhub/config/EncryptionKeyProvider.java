package org.cloudfoundry.credhub.config;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("unused")
public class EncryptionKeyProvider {
  private String providerName;
  private ProviderType providerType;
  private List<EncryptionKeyMetadata> keys = new ArrayList<>();
  private EncryptionConfiguration configuration;

  public EncryptionConfiguration getConfiguration() {
    return configuration;
  }

  public void setConfiguration(EncryptionConfiguration configuration) {
    this.configuration = configuration;
  }

  public String getProviderName() {
    return providerName;
  }

  public void setProviderName(String providerName) {
    this.providerName = providerName;
  }

  public ProviderType getProviderType() {
    return providerType;
  }

  public void setProviderType(ProviderType providerType) {
    this.providerType = providerType;
  }


  public List<EncryptionKeyMetadata> getKeys() {
    return keys;
  }

  public void setKeys(List<EncryptionKeyMetadata> keys) {
    this.keys = keys;
  }

  @Override
  public String toString() {
    return "EncryptionKeyProvider{" +
        "providerName='" + providerName + '\'' +
        ", providerType=" + providerType +
        ", keys=" + keys +
        ", configuration=" + configuration +
        '}';
  }
}
