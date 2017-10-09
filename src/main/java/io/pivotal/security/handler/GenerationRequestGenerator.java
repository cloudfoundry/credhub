package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.service.regeneratables.CertificateCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.NotRegeneratable;
import io.pivotal.security.service.regeneratables.PasswordCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.Regeneratable;
import io.pivotal.security.service.regeneratables.RsaCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.SshCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.UserCredentialRegeneratable;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

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

  public BaseCredentialGenerateRequest createGenerateRequest(CredentialVersion credentialVersion, String credentialName, List<EventAuditRecordParameters> auditRecordParameters) {
    if (credentialVersion == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    Regeneratable regeneratable = regeneratableTypeProducers
        .getOrDefault(credentialVersion.getCredentialType(), NotRegeneratable::new)
        .get();
    return regeneratable.createGenerateRequest(credentialVersion, auditRecordParameters);
  }
}
