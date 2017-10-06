package io.pivotal.security.domain;

import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.entity.CertificateCredentialVersionData;
import io.pivotal.security.entity.CredentialVersionData;
import io.pivotal.security.entity.JsonCredentialVersionData;
import io.pivotal.security.entity.PasswordCredentialVersionData;
import io.pivotal.security.entity.RsaCredentialVersionData;
import io.pivotal.security.entity.SshCredentialVersionData;
import io.pivotal.security.entity.UserCredentialVersionData;
import io.pivotal.security.entity.ValueCredentialVersionData;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CredentialFactory {

  private final Encryptor encryptor;

  @Autowired
  CredentialFactory(Encryptor encryptor) {
    this.encryptor = encryptor;
  }

  public Credential makeCredentialFromEntity(CredentialVersionData credentialVersionData) {
    if (credentialVersionData == null) {
      return null;
    }

    Credential returnValue;
    if (credentialVersionData instanceof CertificateCredentialVersionData) {
      returnValue = new CertificateCredential((CertificateCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof PasswordCredentialVersionData) {
      returnValue = new PasswordCredential((PasswordCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof RsaCredentialVersionData) {
      returnValue = new RsaCredential((RsaCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof SshCredentialVersionData) {
      returnValue = new SshCredential((SshCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof ValueCredentialVersionData) {
      returnValue = new ValueCredential((ValueCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof JsonCredentialVersionData) {
      returnValue = new JsonCredential((JsonCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof UserCredentialVersionData) {
      returnValue = new UserCredential((UserCredentialVersionData) credentialVersionData);
    } else {
      throw new RuntimeException("Unrecognized type: " + credentialVersionData.getClass().getName());
    }

    returnValue.setEncryptor(encryptor);
    return returnValue;
  }

  public List<Credential> makeCredentialsFromEntities(List<CredentialVersionData> daos) {
    return daos.stream().map(this::makeCredentialFromEntity).collect(Collectors.toList());
  }

  public Credential makeNewCredentialVersion(
      CredentialType type,
      String name,
      CredentialValue credentialValue,
      Credential existingCredential,
      GenerationParameters passwordGenerationParameters
  ) {
    Credential credential;
    switch (type) {
      case password:
        credential = new PasswordCredential(
            (StringCredentialValue) credentialValue,
            (StringGenerationParameters) passwordGenerationParameters,
            encryptor);
        break;
      case certificate:
        credential = new CertificateCredential((CertificateCredentialValue) credentialValue, encryptor);
        break;
      case value:
        credential = new ValueCredential((StringCredentialValue) credentialValue, encryptor);
        break;
      case rsa:
        credential = new RsaCredential((RsaCredentialValue) credentialValue, encryptor);
        break;
      case ssh:
        credential = new SshCredential((SshCredentialValue) credentialValue, encryptor);
        break;
      case json:
        credential = new JsonCredential((JsonCredentialValue) credentialValue, encryptor);
        break;
      case user:
        credential = new UserCredential(
            (UserCredentialValue) credentialValue,
            (StringGenerationParameters) passwordGenerationParameters,
            encryptor);
        break;
      default:
        throw new RuntimeException("Unrecognized type: " + type);
    }

    if (existingCredential == null) {
      credential.createName(name);
    } else {
      credential.copyNameReferenceFrom(existingCredential);
    }

    return credential;
  }
}
