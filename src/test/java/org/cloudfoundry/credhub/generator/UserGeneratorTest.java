package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.CryptSaltFactory;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class UserGeneratorTest {

  private UserGenerator subject;

  private StringGenerationParameters passwordParameters;

  @Before
  public void beforeEach() {
    final UsernameGenerator usernameGenerator = mock(UsernameGenerator.class);
    final PasswordCredentialGenerator passwordGenerator = mock(PasswordCredentialGenerator.class);
    final CryptSaltFactory cryptSaltFactory = mock(CryptSaltFactory.class);

    passwordParameters = new StringGenerationParameters();

    subject = new UserGenerator(usernameGenerator, passwordGenerator, cryptSaltFactory);

    final StringCredentialValue generatedUsername = new StringCredentialValue("fake-generated-username");
    final StringCredentialValue generatedPassword = new StringCredentialValue("fake-generated-password");

    when(usernameGenerator.generateCredential())
      .thenReturn(generatedUsername);
    when(passwordGenerator.generateCredential(eq(passwordParameters)))
      .thenReturn(generatedPassword);
    when(cryptSaltFactory.generateSalt(generatedPassword.getStringCredential()))
      .thenReturn("fake-generated-salt");
  }

  @Test
  public void generateCredential_givenAUsernameAndPasswordParameters_generatesUserWithUsernameAndGeneratedPassword() {
    passwordParameters.setUsername("test-user");
    final UserCredentialValue user = subject.generateCredential(passwordParameters);

    assertThat(user.getUsername(), equalTo("test-user"));
    assertThat(user.getPassword(), equalTo("fake-generated-password"));
    assertThat(user.getSalt(), equalTo("fake-generated-salt"));
  }

  @Test
  public void generateCredential_givenNoUsernameAndPasswordParameters_generatesUserWithGeneratedUsernameAndPassword() {
    final UserCredentialValue user = subject.generateCredential(passwordParameters);

    assertThat(user.getUsername(), equalTo("fake-generated-username"));
    assertThat(user.getPassword(), equalTo("fake-generated-password"));
    assertThat(user.getSalt(), equalTo("fake-generated-salt"));
  }
}
