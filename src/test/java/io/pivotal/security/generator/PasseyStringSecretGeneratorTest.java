package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.StringSecretParameters;
import io.pivotal.security.view.StringSecret;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.fit;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;


@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class PasseyStringSecretGeneratorTest {

  @InjectMocks
  @Autowired
  private PasseyStringSecretGenerator subject;

  @Mock
  private CharacterRuleProvider characterRuleProvider;

  @Mock
  private PasswordGenerator passwordGenerator;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  {
    wireAndUnwire(this);

    it("can generate secret", () -> {
      StringSecretParameters secretParameters = new StringSecretParameters();
      secretParameters.setType("value");

      List<CharacterRule> characterRules = new ArrayList<>();

      when(characterRuleProvider.getCharacterRules(same(secretParameters))).thenReturn(characterRules);

      when(passwordGenerator.generatePassword(eq(20), same(characterRules))).thenReturn("very-secret");

      StringSecret secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getValue(), equalTo("very-secret"));
    });

    it("can generate secret with specific length", () -> {
      when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-secret");

      StringSecretParameters secretParameters = new StringSecretParameters();
      secretParameters.setLength(42);
      secretParameters.setType("value");

      StringSecret secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getValue(), equalTo("very-secret"));
    });

    it("ignores too-small length values", () -> {
      when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

      StringSecretParameters secretParameters = new StringSecretParameters();
      secretParameters.setLength(3);
      secretParameters.setType("value");

      StringSecret secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getValue(), equalTo("very-secret"));
    });

    it("ignores too-large length values", () -> {
      when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

      StringSecretParameters secretParameters = new StringSecretParameters();
      secretParameters.setLength(201);
      secretParameters.setType("value");

      StringSecret secretValue = subject.generateSecret(secretParameters);
      assertThat(secretValue.getValue(), equalTo("very-secret"));
    });
  }
}
