package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.service.regeneratables.CertificateCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.NotRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.PasswordCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.Regeneratable;
import org.cloudfoundry.credhub.service.regeneratables.RsaCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.SshCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.UserCredentialRegeneratable;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

@Component
public class GenerationRequestGenerator {
  private Map<String, Supplier<Regeneratable>> regeneratableTypeProducers;

  public GenerationRequestGenerator() {
    this.regeneratableTypeProducers = new HashMap<>();
    this.regeneratableTypeProducers.put("password", PasswordCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("user", UserCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("ssh", SshCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("rsa", RsaCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("certificate", CertificateCredentialRegeneratable::new);
  }

  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion) {
    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    Regeneratable regeneratable = regeneratableTypeProducers
        .getOrDefault(credentialVersion.getCredentialType(), NotRegeneratable::new)
        .get();
    return regeneratable.createGenerateRequest(credentialVersion);
  }
}
