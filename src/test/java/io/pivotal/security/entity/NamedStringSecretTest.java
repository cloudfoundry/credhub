package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.view.StringSecret;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
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
      subject = new NamedStringSecret("Foo");
      ((FakeEncryptionService) encryptionService).setEncryptionCount(0);
      ((FakeEncryptionService) encryptionService).setDecryptionCount(0);
    });

    afterEach(() -> {
      repository.deleteAll();
    });

    it("can create model from entity", () -> {
      subject.setValue("my-value");
      Object actual = subject.generateView();

      assertThat(objectMapper.writer().writeValueAsString(actual), equalTo("{\"type\":\"value\",\"updated_at\":null,\"credential\":\"my-value\"}"));
    });

    it("generated view has updated at", () -> {
      Instant now = Instant.now();
      subject.setValue("my-value")
          .setUpdatedAt(now);

      StringSecret actual = subject.generateView();

      assertThat(actual.getUpdatedAt(), equalTo(now));
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

    itThrows("when setting a value that is null", RuntimeException.class, () -> {
      subject.setValue(null);
    });
  }
}