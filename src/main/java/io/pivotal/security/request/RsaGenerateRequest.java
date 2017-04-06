package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.service.GeneratorService;
import java.util.List;

public class RsaGenerateRequest extends BaseSecretGenerateRequest {

  public static final List<AccessControlEntry> NULL_ACCESS_CONTROL_ENTRIES = null;
  @JsonProperty("parameters")
  private RsaGenerationParameters generationParameters;

  public RsaGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new RsaGenerationParameters();
    }
    return generationParameters;
  }

  public void setGenerationParameters(RsaGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  public BaseSecretSetRequest generateSetRequest(GeneratorService generatorService) {
    RsaSetRequest rsaSetRequest = new RsaSetRequest();
    RsaKey rsaKeys = generatorService.generateRsaKeys(getGenerationParameters());
    rsaSetRequest.setKeySetRequestFields(new KeySetRequestFields(rsaKeys.getPrivateKey(), rsaKeys.getPublicKey()));
    rsaSetRequest.setType(getType());
    rsaSetRequest.setName(getName());
    rsaSetRequest.setOverwrite(isOverwrite());
    rsaSetRequest.setAccessControlEntries(getAccessControlEntries());

    return rsaSetRequest;
  }
}
