package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.when;


@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class PasseyStringSecretGeneratorTest {

  @Autowired
  private PasseyStringSecretGenerator subject;

  @MockBean
  private CharacterRuleProvider characterRuleProvider;

  @MockBean
  private PasswordGenerator passwordGenerator;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  {
    wireAndUnwire(this, false);

    it("can generate secret", () -> {
      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();

      List<CharacterRule> characterRules = new ArrayList<>();

      when(characterRuleProvider.getCharacterRules(same(secretParameters))).thenReturn(characterRules);

      when(passwordGenerator.generatePassword(eq(20), same(characterRules))).thenReturn("very-secret");

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
      when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
      secretParameters.setLength(3);

      Password secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getPassword(), equalTo("very-secret"));
    });

    it("ignores too-large length values", () -> {
      when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

      PasswordGenerationParameters secretParameters = new PasswordGenerationParameters();
      secretParameters.setLength(201);

      Password secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getPassword(), equalTo("very-secret"));
    });
  }
}
