package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertTrue;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedPasswordSecretTest {
    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    Encryptor encryptor;

    NamedPasswordSecret subject;

    PasswordGenerationParameters generationParameters;

    {
        wireAndUnwire(this, false);

        beforeEach(() -> {
            subject = new NamedPasswordSecret("Foo");
            subject.setEncryptor(encryptor);

            generationParameters = new PasswordGenerationParameters();
            generationParameters.setExcludeLower(true);
            generationParameters.setExcludeSpecial(true);
            generationParameters.setLength(10);
        });

        it("returns type password", () -> {
            assertThat(subject.getSecretType(), equalTo("password"));
        });

        describe("with or without alternative names", () -> {
            beforeEach(() -> {
                subject = new NamedPasswordSecret("foo");
                subject.setEncryptor(encryptor);
            });

            it("sets the nonce and the encrypted value", () -> {
                subject.setPasswordAndGenerationParameters("my-value", null);
                assertThat(subject.getEncryptedValue(), notNullValue());
                assertThat(subject.getNonce(), notNullValue());
            });

            it("can decrypt values", () -> {
                subject.setPasswordAndGenerationParameters("my-value", generationParameters);
                assertThat(subject.getPassword(), equalTo("my-value"));
            });

            itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
                subject.setPasswordAndGenerationParameters(null, null);
            });

            it("sets the parametersNonce and the encryptedGenerationParameters", () -> {
                subject.setPasswordAndGenerationParameters("my-value", generationParameters);
                assertThat(subject.getEncryptedGenerationParameters(), notNullValue());
                assertThat(subject.getParametersNonce(), notNullValue());
            });

            it("should set encrypted generation parameters and nonce to null if parameters are null", () -> {
                subject = new NamedPasswordSecret("password-with-null-parameters");
                subject.setEncryptor(encryptor);
                subject.setPasswordAndGenerationParameters("password123", null);
                assertThat(subject.getEncryptedGenerationParameters(), nullValue());
                assertThat(subject.getParametersNonce(), nullValue());
            });


            it("can decrypt values", () -> {
                subject.setPasswordAndGenerationParameters("length10pw", generationParameters);
                assertThat(subject.getGenerationParameters().getLength(), equalTo(10));
                assertThat(subject.getGenerationParameters().isExcludeLower(), equalTo(true));
                assertThat(subject.getGenerationParameters().isExcludeUpper(), equalTo(false));
            });
        });

        describe("#copyInto", () -> {
            it("should copy the correct properties into the other object", () -> {
                Instant frozenTime = Instant.ofEpochSecond(1400000000L);
                UUID uuid = UUID.randomUUID();

                PasswordGenerationParameters parameters = new PasswordGenerationParameters();
                parameters.setExcludeNumber(true);
                parameters.setExcludeLower(true);
                parameters.setExcludeUpper(false);


                subject = new NamedPasswordSecret("foo");
                subject.setEncryptor(encryptor);
                subject.setPasswordAndGenerationParameters("hello", parameters);
                subject.setUuid(uuid);
                subject.setVersionCreatedAt(frozenTime);


                byte[] initialEncryptedValue = subject.getEncryptedValue();
                byte[] initialNonce = subject.getParametersNonce();
                UUID encryptionKeuUuid = subject.getEncryptionKeyUuid();

                NamedPasswordSecret copy = new NamedPasswordSecret();
                subject.copyInto(copy);

                assertThat(copy.getName(), equalTo("foo"));
                assertThat(copy.getPassword(), equalTo("hello"));
                assertThat(copy.getEncryptedValue(), equalTo(initialEncryptedValue));

                assertTrue(equalGenerationParameters(copy.getGenerationParameters(), subject.getGenerationParameters()));
                assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeuUuid));
                assertThat(copy.getParametersNonce(), equalTo(initialNonce));

                assertThat(copy.getUuid(), not(equalTo(uuid)));
                assertThat(copy.getVersionCreatedAt(), not(equalTo(frozenTime)));
            });
        });
    }

    boolean equalGenerationParameters(PasswordGenerationParameters first, PasswordGenerationParameters second) {
        boolean equals = first.getLength() == second.getLength();
        equals = equals && first.isExcludeLower() == second.isExcludeLower();
        equals = equals && first.isExcludeNumber() == second.isExcludeNumber();
        equals = equals && first.isExcludeSpecial() == second.isExcludeSpecial();
        equals = equals && first.isExcludeUpper() == second.isExcludeUpper();
        equals = equals && first.isOnlyHex() == second.isOnlyHex();
        equals = equals && first.isValid() == second.isValid();
        return equals;
    }
}
