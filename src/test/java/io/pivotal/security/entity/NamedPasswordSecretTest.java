package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsNull.notNullValue;

import java.time.Instant;
import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedPasswordSecretTest {
  @Autowired
  ObjectMapper objectMapper;

  NamedPasswordSecret subject;

  PasswordGenerationParameters generationParameters;

  private UUID encryptionKeyUuid;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      subject = new NamedPasswordSecret("Foo");

      generationParameters = new PasswordGenerationParameters();
      generationParameters.setExcludeLower(true);
      generationParameters.setExcludeSpecial(true);
      generationParameters.setLength(10);
    });

    it("returns type password", () -> {
      assertThat(subject.getSecretType(), equalTo("password"));
    });

    describe("#setEncryptionKeyUuid", () -> {
      describe("when there is no parameter encryption key UUID", () -> {
        it("should also set the parameter encryption key UUID", () -> {
          subject = new NamedPasswordSecret("foo");
          encryptionKeyUuid = UUID.randomUUID();
          subject.setEncryptionKeyUuid(encryptionKeyUuid);

          assertThat(subject.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));
          assertThat(subject.getParameterEncryptionKeyUuid(), equalTo(encryptionKeyUuid));
        });
      });

      describe("when there is a parameter encryption key UUID", () -> {
        it("should should not override the existing parameter encryption key UUID", () -> {
          subject = new NamedPasswordSecret("foo");
          UUID parameterEncryptionKeyUuid = UUID.randomUUID();
          subject.setParameterEncryptionKeyUuid(parameterEncryptionKeyUuid);

          encryptionKeyUuid = UUID.randomUUID();
          subject.setEncryptionKeyUuid(encryptionKeyUuid);

          assertThat(subject.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));
          assertThat(subject.getParameterEncryptionKeyUuid(), equalTo(parameterEncryptionKeyUuid));
        });
      });
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedPasswordSecret("foo");
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

    describe("#copyInto", () -> {
      it("should copy the correct properties into the other object", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        UUID encryptionKeyUuid = UUID.randomUUID();
        UUID parameterEncryptionKeyUuid = UUID.randomUUID();

        PasswordGenerationParameters parameters = new PasswordGenerationParameters();
        parameters.setExcludeNumber(true);
        parameters.setExcludeLower(true);
        parameters.setExcludeUpper(false);

        String stringifiedParameters = new ObjectMapper().writeValueAsString(parameters);

        subject = new NamedPasswordSecret("foo");
        subject.setEncryptedValue("value".getBytes());
        subject.setNonce("nonce".getBytes());
        subject.setEncryptedGenerationParameters(stringifiedParameters.getBytes());
        subject.setUuid(uuid);
        subject.setUpdatedAt(frozenTime);
        subject.setEncryptionKeyUuid(encryptionKeyUuid);
        subject.setParameterEncryptionKeyUuid(parameterEncryptionKeyUuid);

        NamedPasswordSecret copy = new NamedPasswordSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("foo"));
        assertThat(copy.getEncryptedValue(), equalTo("value".getBytes()));
        assertThat(copy.getNonce(), equalTo("nonce".getBytes()));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));
        assertThat(copy.getParameterEncryptionKeyUuid(), equalTo(parameterEncryptionKeyUuid));
        assertThat(copy.getEncryptedGenerationParameters(), equalTo(stringifiedParameters.getBytes()));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getUpdatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
