package org.cloudfoundry.credhub.request;

public class CredentialRegenerateRequest extends BaseCredentialRequest {
  @SuppressWarnings("unused")
  public void setRegenerate(final boolean regenerate) { }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
