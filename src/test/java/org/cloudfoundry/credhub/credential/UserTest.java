package org.cloudfoundry.credhub.credential;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class UserTest {
  @Test
  public void getSalt_returnsAConsistentSalt() {
    final String salt = new CryptSaltFactory().generateSalt();
    final UserCredentialValue subject = new UserCredentialValue("test-username", "test-password", salt);

    assertThat(subject.getSalt(), equalTo(salt));
    assertThat(subject.getSalt(), equalTo(salt));
  }

  @Test
  public void getPasswordHash_returnsAConsistentPasswordHash() {
    final String salt = new CryptSaltFactory().generateSalt();
    final UserCredentialValue subject = new UserCredentialValue("test-username", "test-password",
      salt);

    assertThat(subject.getPasswordHash().matches("^\\$6\\$[a-zA-Z0-9/.]{8}\\$[a-zA-Z0-9/.]+$"), equalTo(true));
    assertThat(subject.getPasswordHash(), equalTo(subject.getPasswordHash()));
  }
}
