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
    NamedStringSecret namedSecret = (NamedStringSecret) secretRepository.findOneByName(key);
    if (namedSecret == null) {
      namedSecret = new NamedStringSecret(key);
    }
    namedSecret.setValue(stringSecret.value);
    secretRepository.save(namedSecret);
  }

  @Transactional
  @Override
  public void set(String key, CertificateSecret certificateSecret) {
    NamedCertificateSecret namedCertificateSecret = (NamedCertificateSecret) secretRepository.findOneByName(key);
    if (namedCertificateSecret == null) {
      namedCertificateSecret = new NamedCertificateSecret(key);
    }
    namedCertificateSecret.setCa(certificateSecret.getCertificateBody().getCa());
    namedCertificateSecret.setPub(certificateSecret.getCertificateBody().getPub());
    namedCertificateSecret.setPriv(certificateSecret.getCertificateBody().getPriv());
    secretRepository.save(namedCertificateSecret);
  }

  @Override
  public StringSecret getStringSecret(String key) {
    NamedSecret namedStringSecret = secretRepository.findOneByName(key);
    if (namedStringSecret != null) {
      // todo validate current type
      return new StringSecret(((NamedStringSecret) namedStringSecret).getValue());
    }
    return null;
  }

  @Override
  public CertificateSecret getCertificateSecret(String key) {
    NamedCertificateSecret namedSecret = (NamedCertificateSecret) secretRepository.findOneByName(key);
    if (namedSecret != null) {
      // todo validate type
      return new CertificateSecret(namedSecret.getCa(), namedSecret.getPub(), namedSecret.getPriv());
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
