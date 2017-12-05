package org.cloudfoundry.credhub.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(JUnit4.class)
public class InternalEncryptionConnectionTest {

  @Test
  public void reconnectionWithBC_shouldIgnoreANullException() throws Exception {
    InternalEncryptorConnection connection = new InternalEncryptorConnection();
    connection.reconnect(null);
    // passes
  }

  @Test
  public void reconnectionWithBC_shouldRethrowARealException() {
    InternalEncryptorConnection connection = new InternalEncryptorConnection();
    try {
      connection.reconnect(new RuntimeException("boom"));
      fail("should not make it here");
    } catch (Exception e) {
      assertThat(e.getMessage(), equalTo("boom"));
    }
  }
}
