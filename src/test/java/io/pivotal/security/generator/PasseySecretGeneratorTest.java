package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.SecretParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.passay.CharacterRule;
import org.passay.PasswordGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.when;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class PasseySecretGeneratorTest {

  @InjectMocks
  @Autowired
  private PasseySecretGenerator subject;

  @Mock
  private CharacterRuleProvider characterRuleProvider;

  @Mock
  private PasswordGenerator passwordGenerator;

  @Captor
  private ArgumentCaptor<List<CharacterRule>> captor;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void generateSecret() {
    SecretParameters secretParameters = new SecretParameters();

    List<CharacterRule> characterRules = new ArrayList<>();

    when(characterRuleProvider.getCharacterRules(same(secretParameters))).thenReturn(characterRules);

    when(passwordGenerator.generatePassword(eq(20), same(characterRules))).thenReturn("very-secret");

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));
  }

  @Test
  public void generateSecretWithSpecificLength() {
    when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setLength(42);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));
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

}
