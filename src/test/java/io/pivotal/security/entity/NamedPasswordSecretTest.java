package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

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
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedPasswordSecretTest {

  @Autowired
  SecretRepository repository;

  @Autowired
  ObjectMapper objectMapper;

  @Autowired
  EncryptionService encryptionService;

  NamedPasswordSecret subject;

  PasswordGenerationParameters generationParameters;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedPasswordSecret("Foo");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();

      generationParameters = new PasswordGenerationParameters();
      generationParameters.setExcludeLower(true);
      generationParameters.setExcludeSpecial(true);
      generationParameters.setLength(10);
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedPasswordSecret("foo");
      });

      it("updates the secret value with the same name when overwritten", () -> {
        subject.setValue("my-value1");
        repository.saveAndFlush(subject);
        byte[] firstNonce = subject.getNonce();

        subject.setValue("my-value2");
        repository.saveAndFlush(subject);

        NamedPasswordSecret second = (NamedPasswordSecret) repository.findOne(subject.getId());
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

      it("only encrypts the generationParameters once for the same secret", () -> {
        subject.setGenerationParameters(generationParameters);
        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));

        PasswordGenerationParameters generationParameters2 = new PasswordGenerationParameters();
        generationParameters2.setExcludeLower(true);
        generationParameters2.setExcludeSpecial(true);
        generationParameters2.setLength(10);
        subject.setGenerationParameters(generationParameters2);
        assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
      });

      it("sets the parametersNonce and the encryptedGenerationParameters", () -> {
        subject.setGenerationParameters(generationParameters);
        assertThat(subject.getEncryptedGenerationParameters(), notNullValue());
        assertThat(subject.getParametersNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setValue("length10pw");
        subject.setGenerationParameters(generationParameters);
        assertThat(subject.getGenerationParameters().getLength(), equalTo(10));
        assertThat(subject.getGenerationParameters().isExcludeLower(), equalTo(true));
        assertThat(subject.getGenerationParameters().isExcludeUpper(), equalTo(false));
      });
    });
  }
}
