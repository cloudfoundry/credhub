package io.pivotal.security.request;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringJUnit4ClassRunner.class)
public class UserGenerationParametersTest {

  private UserGenerationParameters userGenerationParameters;

  @Before
  public void beforeEach() {
    userGenerationParameters = new UserGenerationParameters();
  }

  @Test
  public void getUsernameGenerationParameters_returnsDefaultValues() {
    PasswordGenerationParameters parameters = userGenerationParameters
        .getUsernameGenerationParameters();
    assertThat(parameters.getLength(), equalTo(20));
    assertThat(parameters.isExcludeLower(), equalTo(false));
    assertThat(parameters.isExcludeNumber(), equalTo(true));
    assertThat(parameters.isExcludeUpper(), equalTo(false));
    assertThat(parameters.isIncludeSpecial(), equalTo(false));
    assertThat(parameters.isOnlyHex(), equalTo(false));
  }

  @Test
  public void getPasswordGenerationParameters_returnsDefaultValues() {
    PasswordGenerationParameters parameters = userGenerationParameters
        .getPasswordGenerationParameters();
    assertThat(parameters.getLength(), equalTo(30));
    assertThat(parameters.isExcludeLower(), equalTo(false));
    assertThat(parameters.isExcludeNumber(), equalTo(false));
    assertThat(parameters.isExcludeUpper(), equalTo(false));
    assertThat(parameters.isIncludeSpecial(), equalTo(false));
    assertThat(parameters.isOnlyHex(), equalTo(false));
  }
}