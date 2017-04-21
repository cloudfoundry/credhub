package io.pivotal.security.generator;

import io.pivotal.security.request.UserGenerationParameters;
import io.pivotal.security.credential.StringCredential;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGeneratorTest {

  private PassayStringCredentialGenerator passwordGenerator;
  private UserGenerator subject;
  private UserGenerationParameters parameters;

  @Before
  public void beforeEach() {
    passwordGenerator = mock(PassayStringCredentialGenerator.class);
    subject = new UserGenerator(passwordGenerator);

    parameters = new UserGenerationParameters();

    when(passwordGenerator.generateCredential(same(parameters.getPasswordGenerationParameters())))
        .thenReturn(new StringCredential("fake-password"));
    when(passwordGenerator.generateCredential(same(parameters.getUsernameGenerationParameters())))
        .thenReturn(new StringCredential("fake-user"));
  }

  @Test
  public void generateCredential_generatesUsernameAndPassword_withCorrect_generationParameters() {
    assertThat(subject.generateCredential(parameters).getPassword(), equalTo("fake-password"));
    assertThat(subject.generateCredential(parameters).getUsername(), equalTo("fake-user"));
  }

  @Test
  public void generateCredential_generatesOnlyPassword_withNull_usernameParameters() throws Exception{
    parameters.setUsernameGenerationParameters(null);

    when(passwordGenerator.generateCredential(same(parameters.getUsernameGenerationParameters())))
      .thenThrow(NullPointerException.class);

    assertThat(subject.generateCredential(parameters).getPassword(), equalTo("fake-password"));
    assertThat(subject.generateCredential(parameters).getUsername(), is(nullValue()));
  }
}
