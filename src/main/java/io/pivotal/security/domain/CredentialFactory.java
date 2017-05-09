package io.pivotal.security.domain;

import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.CredentialData;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.entity.RsaCredentialData;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.entity.ValueCredentialData;
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

  public Credential makeCredentialFromEntity(CredentialData credentialData) {
    if (credentialData == null) {
      return null;
    }

    Credential returnValue;
    if (credentialData instanceof CertificateCredentialData) {
      returnValue = new CertificateCredential((CertificateCredentialData) credentialData);
    } else if (credentialData instanceof PasswordCredentialData) {
      returnValue = new PasswordCredential((PasswordCredentialData) credentialData);
    } else if (credentialData instanceof RsaCredentialData) {
      returnValue = new RsaCredential((RsaCredentialData) credentialData);
    } else if (credentialData instanceof SshCredentialData) {
      returnValue = new SshCredential((SshCredentialData) credentialData);
    } else if (credentialData instanceof ValueCredentialData) {
      returnValue = new ValueCredential((ValueCredentialData) credentialData);
    } else if (credentialData instanceof JsonCredentialData) {
      returnValue = new JsonCredential((JsonCredentialData) credentialData);
    } else if (credentialData instanceof UserCredentialData) {
      returnValue = new UserCredential((UserCredentialData) credentialData);
    } else {
      throw new RuntimeException("Unrecognized type: " + credentialData.getClass().getName());
    }

    returnValue.setEncryptor(encryptor);
    return returnValue;
  }

  public List<Credential> makeCredentialsFromEntities(List<CredentialData> daos) {
    return daos.stream().map(this::makeCredentialFromEntity).collect(Collectors.toList());
  }

  public Credential makeNewCredentialVersion(
      CredentialType type,
      String name,
      CredentialValue credentialValue,
      Credential existingCredential,
      StringGenerationParameters passwordGenerationParameters
  ) {
    Credential credential;
    switch (type) {
      case password:
        credential = new PasswordCredential((StringCredentialValue) credentialValue,
            passwordGenerationParameters, encryptor);
        break;
      case certificate:
        credential = new CertificateCredential((CertificateCredentialValue) credentialValue,
            encryptor);
        break;
      case value:
        credential = new ValueCredential((StringCredentialValue) credentialValue,
            encryptor);
        break;
      case rsa:
        credential = new RsaCredential((RsaCredentialValue) credentialValue,
            encryptor);
        break;
      case ssh:
        credential = new SshCredential((SshCredentialValue) credentialValue,
            encryptor);
        break;
      case json:
        credential = new JsonCredential((JsonCredentialValue) credentialValue,
            encryptor);
        break;
      case user:
        credential = new UserCredential((UserCredentialValue) credentialValue,
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
