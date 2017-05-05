package io.pivotal.security.credential;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class UserTest {
  @Test
  public void getSalt_returnsAConsistentSalt() {
    UserCredentialValue subject = new UserCredentialValue("test-username", "test-password", "test-salt");

    assertThat(subject.getSalt(), equalTo("test-salt"));
  }

  @Test
  public void getPasswordHash_returnsAConsistentPasswordHash() {
    UserCredentialValue subject = new UserCredentialValue("test-username", "test-password", "$6$fakesalt");

    assertThat(subject.getPasswordHash().matches("^\\$6\\$[a-zA-Z0-9/.]+\\$[a-zA-Z0-9/.]+$"), equalTo(true));
    assertThat(subject.getPasswordHash(), equalTo(subject.getPasswordHash()));
  }
}
