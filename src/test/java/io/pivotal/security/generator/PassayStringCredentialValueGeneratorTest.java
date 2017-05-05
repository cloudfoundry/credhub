package io.pivotal.security.generator;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.request.StringGenerationParameters;
import java.util.List;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;


@RunWith(Spectrum.class)
public class PassayStringCredentialValueGeneratorTest {

  private PasswordGenerator passwordGenerator;
  private PassayStringCredentialGenerator subject;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  {
    beforeEach(() -> {
      passwordGenerator = mock(PasswordGenerator.class);
      subject = new PassayStringCredentialGenerator(passwordGenerator);
    });

    it("can generate credential", () -> {
      StringGenerationParameters generationParameters = new StringGenerationParameters();

      when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), any(List.class)))
          .thenReturn("very-credential");

      StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
      assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
    });

    it("can generate credential with specific length", () -> {
      when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-credential");

      StringGenerationParameters generationParameters = new StringGenerationParameters();
      generationParameters.setLength(42);

      StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
      assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
    });

    it("ignores too-small length values", () -> {
      when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
          .thenReturn("very-credential");

      StringGenerationParameters generationParameters = new StringGenerationParameters();
      generationParameters.setLength(3);

      StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
      assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
    });

    it("ignores too-large length values", () -> {
      when(passwordGenerator.generatePassword(eq(subject.DEFAULT_LENGTH), anyList()))
          .thenReturn("very-credential");

      StringGenerationParameters generationParameters = new StringGenerationParameters();
      generationParameters.setLength(201);

      StringCredentialValue stringCredentialValue = subject.generateCredential(generationParameters);
      assertThat(stringCredentialValue.getStringCredential(), equalTo("very-credential"));
    });
  }
}
