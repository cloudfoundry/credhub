package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.view.StringSecret;
import io.pivotal.security.controller.v1.StringSecretParameters;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class PasseyStringSecretGeneratorTest extends MockitoSpringTest {

  @InjectMocks
  @Autowired
  private PasseyStringSecretGenerator subject;

  @Mock
  private CharacterRuleProvider characterRuleProvider;

  @Mock
  private PasswordGenerator passwordGenerator;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  @Test
  public void generateSecret() {
    StringSecretParameters secretParameters = new StringSecretParameters();

    List<CharacterRule> characterRules = new ArrayList<>();

    when(characterRuleProvider.getCharacterRules(same(secretParameters))).thenReturn(characterRules);

    when(passwordGenerator.generatePassword(eq(20), same(characterRules))).thenReturn("very-secret");

    StringSecret secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue.getValue(), equalTo("very-secret"));
  }

  @Test
  public void generateSecretWithSpecificLength() {
    when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-secret");

    StringSecretParameters secretParameters = new StringSecretParameters();
    secretParameters.setLength(42);

    StringSecret secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue.getValue(), equalTo("very-secret"));
  }

  @Test
  public void generateSecretWithLessThanMinLength() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    StringSecretParameters secretParameters = new StringSecretParameters();
    secretParameters.setLength(3);

    StringSecret secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue.getValue(), equalTo("very-secret"));
  }

  @Test
  public void generateSecretWithMoreThanMaxLength() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    StringSecretParameters secretParameters = new StringSecretParameters();
    secretParameters.setLength(201);

    StringSecret secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue.getValue(), equalTo("very-secret"));
  }

}
