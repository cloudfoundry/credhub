package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.model.CertificateSecret;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class NamedCertificateSecretTest {
  @Test
  public void canCreateModelFromEntity() throws Exception {
    NamedCertificateSecret subject = new NamedCertificateSecret("Foo");
    subject.setCa("my-ca").setPub("my-pub").setPriv("my-priv");
    Object actual = subject.convertToModel();
    assertThat(new ObjectMapper().writer().writeValueAsString(actual), equalTo("{\"type\":\"certificate\",\"certificate\":{\"ca\":\"my-ca\",\"public\":\"my-pub\",\"private\":\"my-priv\"}}"));
  }
}