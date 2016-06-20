package io.pivotal.security.model;

import io.pivotal.security.CredentialManagerApp;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class StringSecretParametersTest {

  @Test
  public void isValid_returnsFalseIfEverythingIsExcluded() {
    doTest(false, true, true, true, true);
    doTest(true, true, true, true, false);
    doTest(true, true, true, false, true);
    doTest(true, true, true, false, false);
    doTest(true, true, false, true, true);
    doTest(true, true, false, true, false);
    doTest(true, true, false, false, true);
    doTest(true, true, false, false, false);
    doTest(true, false, true, true, true);
    doTest(true, false, true, true, false);
    doTest(true, false, true, false, true);
    doTest(true, false, true, false, false);
    doTest(true, false, false, true, true);
    doTest(true, false, false, true, false);
    doTest(true, false, false, false, true);
    doTest(true, false, false, false, false);
  }

  private void doTest(boolean expected, boolean excludeLower, boolean excludeUpper, boolean excludeSpecial, boolean excludeNumber) {
    StringSecretParameters stringSecretParameters = new StringSecretParameters()
        .setExcludeLower(excludeLower)
        .setExcludeUpper(excludeUpper)
        .setExcludeNumber(excludeNumber)
        .setExcludeSpecial(excludeSpecial);
    assertThat(stringSecretParameters.isValid(), equalTo(expected));
  }

  @Test
  public void checkEqualityReturnsFalseIfParamsNotEqual() {
    StringSecretParameters params = new StringSecretParameters();
    params.setExcludeLower(true);
    params.setExcludeUpper(true);
    params.setExcludeNumber(true);

    StringSecretParameters params2 = new StringSecretParameters();
    params2.setExcludeLower(true);
    params2.setExcludeUpper(true);
    params2.setExcludeNumber(false);

    Assert.assertThat(params.equals(params2), is(false));
  }
}