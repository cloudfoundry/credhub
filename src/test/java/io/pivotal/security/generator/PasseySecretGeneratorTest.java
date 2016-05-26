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

import static org.hamcrest.CoreMatchers.equalTo;
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
  public void generateSecretWithDefaultParameters() throws Exception {
    when(passwordGenerator.generatePassword(eq(20), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(20), captor.capture());
    assertThat(captor.getValue().size(), equalTo(4));
  }

  @Test
  public void generateSecretWithSpecificLength() throws Exception {
    when(passwordGenerator.generatePassword(eq(42), anyList())).thenReturn("very-secret");

    SecretParameters secretParameters = new SecretParameters();
    secretParameters.setLength(42);

    String secretValue = subject.generateSecret(secretParameters);
    assertThat(secretValue, equalTo("very-secret"));

    Mockito.verify(passwordGenerator).generatePassword(eq(42), captor.capture());
    assertThat(captor.getValue().size(), equalTo(4));
  }

}