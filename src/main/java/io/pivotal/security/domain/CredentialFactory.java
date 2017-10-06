package io.pivotal.security.domain;

import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.credential.RsaCredentialValue;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.entity.CertificateCredentialVersion;
import io.pivotal.security.entity.CredentialVersion;
import io.pivotal.security.entity.JsonCredentialVersion;
import io.pivotal.security.entity.PasswordCredentialVersion;
import io.pivotal.security.entity.RsaCredentialVersion;
import io.pivotal.security.entity.SshCredentialVersion;
import io.pivotal.security.entity.UserCredentialVersion;
import io.pivotal.security.entity.ValueCredentialVersion;
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

  public Credential makeCredentialFromEntity(CredentialVersion credentialVersion) {
    if (credentialVersion == null) {
      return null;
    }

    Credential returnValue;
    if (credentialVersion instanceof CertificateCredentialVersion) {
      returnValue = new CertificateCredential((CertificateCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof PasswordCredentialVersion) {
      returnValue = new PasswordCredential((PasswordCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof RsaCredentialVersion) {
      returnValue = new RsaCredential((RsaCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof SshCredentialVersion) {
      returnValue = new SshCredential((SshCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof ValueCredentialVersion) {
      returnValue = new ValueCredential((ValueCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof JsonCredentialVersion) {
      returnValue = new JsonCredential((JsonCredentialVersion) credentialVersion);
    } else if (credentialVersion instanceof UserCredentialVersion) {
      returnValue = new UserCredential((UserCredentialVersion) credentialVersion);
    } else {
      throw new RuntimeException("Unrecognized type: " + credentialVersion.getClass().getName());
    }

    returnValue.setEncryptor(encryptor);
    return returnValue;
  }

  public List<Credential> makeCredentialsFromEntities(List<CredentialVersion> daos) {
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
