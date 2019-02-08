package org.cloudfoundry.credhub.domain;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;

@Component
public class CredentialFactory {

  private final Encryptor encryptor;

  @Autowired
  CredentialFactory(final Encryptor encryptor) {
    super();
    this.encryptor = encryptor;
  }

  public CredentialVersion makeCredentialFromEntity(final CredentialVersionData credentialVersionData) {
    if (credentialVersionData == null) {
      return null;
    }

    final CredentialVersion returnValue;
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

  public List<CredentialVersion> makeCredentialsFromEntities(final List<CredentialVersionData> daos) {
    return daos.stream().map(this::makeCredentialFromEntity).collect(Collectors.toList());
  }

  public CredentialVersion makeNewCredentialVersion(
    final CredentialType type,
    final String name,
    final CredentialValue credentialValue,
    final CredentialVersion existingCredentialVersion,
    final GenerationParameters passwordGenerationParameters
  ) {
    final CredentialVersion credentialVersion;
    switch (type) {
      case PASSWORD:
        credentialVersion = new PasswordCredentialVersion(
          (StringCredentialValue) credentialValue,
          (StringGenerationParameters) passwordGenerationParameters,
          encryptor
        );
        break;
      case CERTIFICATE:
        credentialVersion = new CertificateCredentialVersion((CertificateCredentialValue) credentialValue, encryptor);
        break;
      case VALUE:
        credentialVersion = new ValueCredentialVersion((StringCredentialValue) credentialValue, encryptor);
        break;
      case RSA:
        credentialVersion = new RsaCredentialVersion((RsaCredentialValue) credentialValue, encryptor);
        break;
      case SSH:
        credentialVersion = new SshCredentialVersion((SshCredentialValue) credentialValue, encryptor);
        break;
      case JSON:
        credentialVersion = new JsonCredentialVersion((JsonCredentialValue) credentialValue, encryptor);
        break;
      case USER:
        credentialVersion = new UserCredentialVersion(
          (UserCredentialValue) credentialValue,
          (StringGenerationParameters) passwordGenerationParameters,
          encryptor
        );
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
