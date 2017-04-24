package io.pivotal.security.generator;

import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.credential.User;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGeneratorTest {

  private UserGenerator subject;

  private StringGenerationParameters passwordParameters;

  @Before
  public void beforeEach() {
    UsernameGenerator usernameGenerator = mock(UsernameGenerator.class);
    PasswordCredentialGenerator passwordGenerator = mock(PasswordCredentialGenerator.class);

    passwordParameters = mock(StringGenerationParameters.class);

    subject = new UserGenerator(usernameGenerator, passwordGenerator);

    StringCredential generatedUsername = new StringCredential("fake-generated-username");
    StringCredential generatedPassword = new StringCredential("fake-generated-password");

    when(usernameGenerator.generateCredential()).thenReturn(generatedUsername);
    when(passwordGenerator.generateCredential(passwordParameters)).thenReturn(generatedPassword);
  }

  @Test
  public void generateCredential_givenAUsernameAndPasswordParameters_generatesUserWithUsernameAndGeneratedPassword() {
    final User user = subject.generateCredential("test-user", passwordParameters);

    assertThat(user.getUsername(), equalTo("test-user"));
    assertThat(user.getPassword(), equalTo("fake-generated-password"));
  }

  @Test
  public void generateCredential_givenNoUsernameAndPasswordParameters_generatesUserWithGeneratedUsernameAndPassword() {
    final User user = subject.generateCredential(null, passwordParameters);

    assertThat(user.getUsername(), equalTo("fake-generated-username"));
    assertThat(user.getPassword(), equalTo("fake-generated-password"));
  }
}
