package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.view.CertificateSecret;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.time.LocalDateTime;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
 
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class NamedCertificateSecretTest {

  @Autowired
  private ObjectMapper objectMapper;

  @Test
  public void canCreateModelFromEntity() throws Exception {
    NamedCertificateSecret subject = NamedCertificateSecret.make("Foo", "my-ca", "my-pub", "my-priv");
    Object actual = subject.generateView();
    assertThat(objectMapper.writer().writeValueAsString(actual), equalTo("{\"type\":\"certificate\",\"updated_at\":null,\"certificate\":{\"ca\":\"my-ca\",\"public\":\"my-pub\",\"private\":\"my-priv\"}}"));
  }

  @Test
  public void convertToModel_setsUpdatedAtFromEntity() {
    LocalDateTime now = LocalDateTime.now();
    NamedCertificateSecret subject = new NamedCertificateSecret("Foo")
        .setUpdatedAt(now);
    CertificateSecret actual = subject.generateView();
    assertThat(actual.getUpdatedAt(), equalTo(now));
  }
}