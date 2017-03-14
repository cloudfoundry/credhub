package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;

import java.util.List;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(Spectrum.class)
public class PassayStringSecretGeneratorTest {
  private PasswordGenerator passwordGenerator;
  private PassayStringSecretGenerator subject;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  {
    beforeEach(() -> {
      passwordGenerator = mock(PasswordGenerator.class);
      subject = new PassayStringSecretGenerator(passwordGenerator);
    });

    it("can generate secret", () -> {
      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();

      when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), any(List.class))).thenReturn("very-secret");

      Password secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getPassword(), equalTo("very-secret"));
    });

    it("can generate secret with specific length", () -> {
      when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-secret");

      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
      secretParameters.setLength(42);

      Password secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getPassword(), equalTo("very-secret"));
    });

    it("ignores too-small length values", () -> {
      when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList())).thenReturn("very-secret");

      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
      secretParameters.setLength(3);

      Password secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getPassword(), equalTo("very-secret"));
    });

    it("ignores too-large length values", () -> {
      when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList())).thenReturn("very-secret");

      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
      secretParameters.setLength(201);

      Password secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getPassword(), equalTo("very-secret"));
    });
  }
}
