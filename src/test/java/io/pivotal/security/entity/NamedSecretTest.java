package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.repository.SecretRepository;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class NamedSecretTest {
  @Autowired
  SecretRepository repository;

  private Consumer<Long> fakeTimeSetter;
  private NamedCertificateSecret secret;

  {
    wireAndUnwire(this);
    autoTransactional(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(345345L);
      secret = io.pivotal.security.entity.NamedCertificateSecret.make("foo", "ca", "pub", "priv");
    });

    it("returns date created", () -> {
      secret = repository.save(secret);
      assertThat(repository.findOneByName("foo").getUpdatedAt().toEpochMilli(), equalTo(345345L));
    });

    it("returns date updated", () -> {
      secret = repository.save(secret);
      fakeTimeSetter.accept(444444L);
      secret.setPrivateKey("new-priv");  // Change object so that Hibernate will update the database
      secret = repository.save(secret);
      assertThat(repository.findOneByName("foo").getUpdatedAt().toEpochMilli(), equalTo(444444L));
    });
  }
}