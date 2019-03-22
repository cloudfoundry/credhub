package org.cloudfoundry.credhub.testdoubles;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.service.regeneratables.CertificateCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.NotRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.PasswordCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.Regeneratable;
import org.cloudfoundry.credhub.service.regeneratables.RsaCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.SshCredentialRegeneratable;
import org.cloudfoundry.credhub.service.regeneratables.UserCredentialRegeneratable;

@Component
public class GenerationRequestGenerator {
  private final Map<String, Supplier<Regeneratable>> regeneratableTypeProducers;

  public GenerationRequestGenerator() {
    super();
    this.regeneratableTypeProducers = new HashMap<>();
    this.regeneratableTypeProducers.put("password", PasswordCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("user", UserCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("ssh", SshCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("rsa", RsaCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("certificate", CertificateCredentialRegeneratable::new);
  }

  public BaseCredentialGenerateRequest createGenerateRequest(final CredentialVersion credentialVersion) {
    if (credentialVersion == null) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }
    final Regeneratable regeneratable = regeneratableTypeProducers
      .getOrDefault(credentialVersion.getCredentialType(), NotRegeneratable::new)
      .get();
    return regeneratable.createGenerateRequest(credentialVersion);
  }
}
