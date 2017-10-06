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

  public CredentialVersion makeCredentialFromEntity(CredentialVersionData credentialVersionData) {
    if (credentialVersionData == null) {
      return null;
    }

    CredentialVersion returnValue;
    if (credentialVersionData instanceof CertificateCredentialVersionData) {
      returnValue = new CertificateCredentialVersion((CertificateCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof PasswordCredentialVersionData) {
      returnValue = new PasswordCredentialVersion((PasswordCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof RsaCredentialVersionData) {
      returnValue = new RsaCredentialVersion((RsaCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof SshCredentialVersionData) {
      returnValue = new SshCredentialVersion((SshCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof ValueCredentialVersionData) {
      returnValue = new ValueCredentialVersion((ValueCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof JsonCredentialVersionData) {
      returnValue = new JsonCredentialVersion((JsonCredentialVersionData) credentialVersionData);
    } else if (credentialVersionData instanceof UserCredentialVersionData) {
      returnValue = new UserCredentialVersion((UserCredentialVersionData) credentialVersionData);
    } else {
      throw new RuntimeException("Unrecognized type: " + credentialVersionData.getClass().getName());
    }

    returnValue.setEncryptor(encryptor);
    return returnValue;
  }

  public List<CredentialVersion> makeCredentialsFromEntities(List<CredentialVersionData> daos) {
    return daos.stream().map(this::makeCredentialFromEntity).collect(Collectors.toList());
  }

  public CredentialVersion makeNewCredentialVersion(
      CredentialType type,
      String name,
      CredentialValue credentialValue,
      CredentialVersion existingCredentialVersion,
      GenerationParameters passwordGenerationParameters
  ) {
    CredentialVersion credentialVersion;
    switch (type) {
      case password:
        credentialVersion = new PasswordCredentialVersion(
            (StringCredentialValue) credentialValue,
            (StringGenerationParameters) passwordGenerationParameters,
            encryptor);
        break;
      case certificate:
        credentialVersion = new CertificateCredentialVersion((CertificateCredentialValue) credentialValue, encryptor);
        break;
      case value:
        credentialVersion = new ValueCredentialVersion((StringCredentialValue) credentialValue, encryptor);
        break;
      case rsa:
        credentialVersion = new RsaCredentialVersion((RsaCredentialValue) credentialValue, encryptor);
        break;
      case ssh:
        credentialVersion = new SshCredentialVersion((SshCredentialValue) credentialValue, encryptor);
        break;
      case json:
        credentialVersion = new JsonCredentialVersion((JsonCredentialValue) credentialValue, encryptor);
        break;
      case user:
        credentialVersion = new UserCredentialVersion(
            (UserCredentialValue) credentialValue,
            (StringGenerationParameters) passwordGenerationParameters,
            encryptor);
        break;
      default:
        throw new RuntimeException("Unrecognized type: " + type);
    }

    if (existingCredentialVersion == null) {
      credentialVersion.createName(name);
    } else {
      credentialVersion.copyNameReferenceFrom(existingCredentialVersion);
    }

    return credentialVersion;
  }
}
