package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedStringSecretTest {
  @Autowired
  SecretRepository repository;

  @Autowired
  public ObjectMapper objectMapper;

  @Autowired
  EncryptionService encryptionService;

  NamedStringSecret subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedStringSecret("Foo", "value");
      ((FakeEncryptionService) encryptionService).setEncryptionCount(0);
    });

    afterEach(() -> {
      repository.deleteAll();
    });

    describe("secret types", () -> {
      itThrows("disallows null for secret types", IllegalArgumentException.class, () -> {
        subject.setSecretType(null);
        repository.saveAndFlush(subject);
      });

      itThrows("disallows unknown secret types", IllegalArgumentException.class, () -> {
        subject.setSecretType("foo");
        repository.saveAndFlush(subject);
      });

      itThrows("disallows unknown secret types", IllegalArgumentException.class, () -> {
        subject = new NamedStringSecret("Foo", "foo");
        repository.saveAndFlush(subject);
      });

      it("allows 'value' or 'password' for secret type ", () -> {
        repository.saveAndFlush(subject);

        NamedStringSecret found = (NamedStringSecret) repository.findOne(subject.getId());
        assertThat(found.getSecretType(), equalTo("value"));

        subject.setSecretType("password");
        repository.saveAndFlush(subject);

        found = (NamedStringSecret) repository.findOne(subject.getId());
        assertThat(found.getSecretType(), equalTo("password"));
      });
    });

    describe("value string secrets", validateNamedStringSecret(new NamedStringSecret("foo", "value")));

    describe("password string secrets", validateNamedStringSecret(new NamedStringSecret("foo", "password")));
  }

  private Spectrum.Block validateNamedStringSecret(NamedStringSecret namedStringSecret) {
    return  () -> {
      describe("with or without alternative names", () -> {
        beforeEach(() -> {
          subject = namedStringSecret;
        });

        it("updates the secret value with the same name when overwritten", () -> {
          subject.setValue("my-value1");
          repository.saveAndFlush(subject);
          byte[] firstNonce = subject.getNonce();

          subject.setValue("my-value2");
          repository.saveAndFlush(subject);

          NamedStringSecret second = (NamedStringSecret) repository.findOne(subject.getId());
          assertThat(second.getValue(), equalTo("my-value2"));
          assertThat(Arrays.equals(firstNonce, second.getNonce()), is(false));
        });

        it("only encrypts the value once for the same secret", () -> {
          subject.setValue("my-value");
          assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));

          subject.setValue("my-value");
          assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
        });

        it("sets the nonce and the encrypted value", () -> {
          subject.setValue("my-value");
          assertThat(subject.getEncryptedValue(), notNullValue());
          assertThat(subject.getNonce(), notNullValue());
        });

        it("can decrypt values", () -> {
          subject.setValue("my-value");
          assertThat(subject.getValue(), equalTo("my-value"));
        });

        itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
          subject.setValue(null);
        });

        it("sets UUID when Hibernate stores the object", () -> {
          subject.setValue("my-value");
          repository.save(subject);
          assertThat(subject.getUuid().length(), equalTo(36));
        });
      });
    };
  }
}