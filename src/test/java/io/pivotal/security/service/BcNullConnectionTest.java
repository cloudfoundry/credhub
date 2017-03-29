package io.pivotal.security.service;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class BcNullConnectionTest {

  {
    describe("reconnecting with BouncyCastle", () -> {
      it("should ignore a null exception", () -> {
        BcNullConnection connection = new BcNullConnection();
        connection.reconnect(null);
        // passes
      });

      it("should rethrow a real exception", () -> {
        BcNullConnection connection = new BcNullConnection();
        try {
          connection.reconnect(new RuntimeException("boom"));
          fail("should not make it here");
        } catch (Exception e) {
          assertThat(e.getMessage(), equalTo("boom"));
        }
      });
    });
  }
}
