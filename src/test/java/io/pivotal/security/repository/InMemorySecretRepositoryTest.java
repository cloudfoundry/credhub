package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedStringSecret;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.stream.Stream;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class InMemorySecretRepositoryTest {

  @Autowired
  InMemorySecretRepository subject;

  @Test
  @Transactional
  public void canStoreStringsOfLength7000() throws Exception {
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedStringSecret entity = new NamedStringSecret("my-secret");
    entity.setValue(stringBuilder.toString());

    subject.save(entity);
    assertThat(((NamedStringSecret) subject.findOneByName("my-secret")).getValue().length(), equalTo(7000));

    try {
      stringBuilder.append("b");
      entity.setValue(stringBuilder.toString());
      subject.flush();
      fail();
    } catch (DataIntegrityViolationException e) {
      // exception expected
    }
  }
}