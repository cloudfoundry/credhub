package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedSshSecretTest {
  @Autowired
  SecretRepository repository;

  @Autowired
  EncryptionService encryptionService;

  private NamedSshSecret subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedSshSecret("Foo");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    it("sets a public key", () -> {
      subject
          .setPublicKey("my-public-key");
      repository.saveAndFlush(subject);
      NamedSshSecret result = (NamedSshSecret) repository.findOne(subject.getId());
      assertThat(result.getPublicKey(), equalTo("my-public-key"));
    });

    it("sets an encrypted private key", () -> {
      subject
          .setPrivateKey("some-private-value");
      repository.saveAndFlush(subject);

      NamedSshSecret result = (NamedSshSecret) repository.findOne(subject.getId());

      assertThat(result.getPrivateKey(), equalTo("some-private-value"));
    });

    it("updates the private key value with the same name when overwritten", () -> {
      subject.setPrivateKey("first");
      repository.saveAndFlush(subject);

      subject.setPrivateKey("second");
      repository.saveAndFlush(subject);

      NamedSshSecret result = (NamedSshSecret) repository.findOne(subject.getId());
      assertThat(result.getPrivateKey(), equalTo("second"));
    });

  }
}
