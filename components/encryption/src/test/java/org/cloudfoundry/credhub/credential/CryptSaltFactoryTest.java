package org.cloudfoundry.credhub.credential;

import org.cloudfoundry.credhub.CryptSaltFactory;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class CryptSaltFactoryTest {
  @Test
  public void generateSalt_returnsCorrectlyFormattedSalt() {
    final String salt = new CryptSaltFactory().generateSalt();

    assertThat(salt.matches("^\\$6\\$[a-zA-Z0-9/.]{8}$"), equalTo(true));
  }

  @Test
  public void generateSalt_returnsDifferentValuesOnEachCall() {
    final CryptSaltFactory cryptSaltFactory = new CryptSaltFactory();
    final String salt1 = cryptSaltFactory.generateSalt();
    final String salt2 = cryptSaltFactory.generateSalt();

    assertThat(salt1, not(equalTo(salt2)));
  }
}
