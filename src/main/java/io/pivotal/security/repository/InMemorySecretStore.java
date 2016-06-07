package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.StringSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class InMemorySecretStore implements SecretStore {

  private final InMemorySecretRepository secretRepository;

  @Autowired
  public InMemorySecretStore(InMemorySecretRepository secretRepository) {
    this.secretRepository = secretRepository;
  }

  @Transactional
  @Override
  public void set(String key, StringSecret stringSecret) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret == null) {
      NamedStringSecret namedStringSecret = new NamedStringSecret(key, stringSecret.value);
      namedSecret = namedStringSecret;
    } else {
      // todo validate current type is string
      ((NamedStringSecret)namedSecret).value = stringSecret.value;
    }
    secretRepository.save(namedSecret);
  }

  @Transactional
  @Override
  public void set(String key, CertificateSecret certificateSecret) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret == null) {
      NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret(
          key,
          certificateSecret.certificateBody.ca,
          certificateSecret.certificateBody.pub,
          certificateSecret.certificateBody.priv);
      namedSecret = namedCertificateSecret;
    } else {
      // todo validate current type
      NamedCertificateSecret namedCertificateSecret = (NamedCertificateSecret) namedSecret;
      namedCertificateSecret.ca = certificateSecret.certificateBody.ca;
      namedCertificateSecret.pub = certificateSecret.certificateBody.pub;
      namedCertificateSecret.priv = certificateSecret.certificateBody.priv;
    }
    secretRepository.save(namedSecret);
  }

  @Override
  public StringSecret getStringSecret(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      // todo validate current type
        return StringSecret.make(((NamedStringSecret)namedSecret).value);
    }
    return null;
  }

  @Override
  public CertificateSecret getCertificateSecret(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      // todo validate type
      NamedCertificateSecret namedCertificateSecret = (NamedCertificateSecret) namedSecret;
      CertificateSecret secret = new CertificateSecret(namedCertificateSecret.ca, namedCertificateSecret.pub, namedCertificateSecret.priv);
      return secret;
    }
    return null;
  }

  @Transactional
  @Override
  public boolean delete(String key) {
    NamedSecret namedSecret = secretRepository.findOneByName(key);
    if (namedSecret != null) {
      secretRepository.delete(namedSecret);
      return true;
    }
    return false;
  }
}
