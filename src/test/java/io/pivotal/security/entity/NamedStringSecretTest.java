package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.view.StringSecret;
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
public class NamedStringSecretTest {

  @Autowired
  public ObjectMapper objectMapper;

  @Test
  public void canCreateModelFromEntity() throws Exception {
    NamedStringSecret subject = new NamedStringSecret("Foo")
        .setValue("my-value");

    Object actual = subject.generateView();

    assertThat(objectMapper.writer().writeValueAsString(actual), equalTo("{\"value\":\"my-value\",\"type\":\"value\",\"updated_at\":null}"));
  }

  @Test
  public void convertToModel_setsUpdatedAtFromEntity() {
    NamedStringSecret subject = new NamedStringSecret("Foo");
    LocalDateTime now = LocalDateTime.now();
    subject.setUpdatedAt(now);

    StringSecret actual = subject.generateView();

    assertThat(actual.getUpdatedAt(), equalTo(now));
  }
}