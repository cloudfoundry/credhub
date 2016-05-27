package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.SecretParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.List;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class PasseySecretGeneratorTest {

  @InjectMocks
  @Autowired
  private PasseySecretGenerator subject;

  @Mock
  private PasswordGenerator passwordGenerator;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void generateSecretWithDefaultParameters() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(20), captor.capture());
    assertThat(captor.getValue().size(), equalTo(4));
  }

  @Test
  public void generateSecretWithSpecificLength() {
    when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setLength(42);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(42), captor.capture());
    assertThat(captor.getValue().size(), equalTo(4));
  }

  @Test
  public void generateSecretWithLessThanMinLength() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setLength(3);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));
  }

  @Test
  public void generateSecretWithMoreThanMaxLength() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setLength(201);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));
  }

  @Test
  public void generateSecretWithoutUppercase() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeUpper(true);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(20), captor.capture());

    List<CharacterRule> characterRules = captor.getValue();
    assertThat(characterRules.size(), equalTo(3));

    for (CharacterRule characterRule : characterRules) {
      assertThat(characterRule.getValidCharacters(), not(containsString("ABC")));
    }
  }

  @Test
  public void generateSecretWithoutLowercase() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeLower(true);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(20), captor.capture());

    List<CharacterRule> characterRules = captor.getValue();
    assertThat(characterRules.size(), equalTo(3));

    for (CharacterRule characterRule : characterRules) {
      assertThat(characterRule.getValidCharacters(), not(containsString("abc")));
    }
  }

  @Test
  public void generateSecretWithoutSpecial() {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setExcludeSpecial(true);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(20), captor.capture());

    List<CharacterRule> characterRules = captor.getValue();
    assertThat(characterRules.size(), equalTo(3));

    for (CharacterRule characterRule : characterRules) {
      assertThat(characterRule.getValidCharacters(), not(containsString("*")));
    }
  }

}
