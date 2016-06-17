package io.pivotal.security.model;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

public class CertificateSecretTest {
  private CertificateSecret model;

  @Before
  public void setUp() throws Exception {
    model = new CertificateSecret("ca", "pub", "priv");
  }

  @Test
  public void makeEntityCreatesNewEntity() throws Exception {
    assertThat(model.makeEntity("myName"), instanceOf(NamedCertificateSecret.class));
  }

  @Test
  public void populateEntityEnsuresModelValuesAreInEntity() throws Exception {
    NamedCertificateSecret entity = new NamedCertificateSecret();
    model.populateEntity(entity);
    assertThat(entity.getCa(), equalTo("ca"));
    assertThat(entity.getPub(), equalTo("pub"));
    assertThat(entity.getPriv(), equalTo("priv"));
  }

}