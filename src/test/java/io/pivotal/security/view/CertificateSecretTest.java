package io.pivotal.security.view;

import io.pivotal.security.entity.NamedCertificateSecret;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class CertificateSecretTest {
  private CertificateSecret model;

  @Before
  public void setUp() throws Exception {
    model = new CertificateSecret("ca", "pub", "priv");
  }

  @Test
  public void populateEntityEnsuresModelValuesAreInEntity() throws Exception {
    NamedCertificateSecret entity = new NamedCertificateSecret();
    model.populateEntity(entity);
    assertThat(entity.getRoot(), equalTo("ca"));
    assertThat(entity.getCertificate(), equalTo("pub"));
    assertThat(entity.getPrivateKey(), equalTo("priv"));
  }
}