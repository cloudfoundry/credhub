package io.pivotal.security.generator;

import io.pivotal.security.request.UserGenerationParameters;
import io.pivotal.security.secret.Password;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGeneratorTest {

  private PassayStringSecretGenerator passwordGenerator;
  private UserGenerator subject;
  private UserGenerationParameters parameters;

  @Before
  public void beforeEach() {
    passwordGenerator = mock(PassayStringSecretGenerator.class);
    subject = new UserGenerator(passwordGenerator);

    parameters = new UserGenerationParameters();

    when(passwordGenerator.generateSecret(same(parameters.getPasswordGenerationParameters())))
        .thenReturn(new Password("fake-password"));
    when(passwordGenerator.generateSecret(same(parameters.getUsernameGenerationParameters())))
        .thenReturn(new Password("fake-user"));
  }

  @Test
  public void generateSecret_generatesUsernameAndPassword_withCorrect_generationParameters() {
    assertThat(subject.generateSecret(parameters).getPassword(),
        equalTo("fake-password"));
    assertThat(subject.generateSecret(parameters).getUsername(),
        equalTo("fake-user"));
  }
}