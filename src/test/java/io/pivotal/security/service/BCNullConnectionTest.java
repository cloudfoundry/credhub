package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(Spectrum.class)
public class BCNullConnectionTest {

  {
    describe("reconnecting with BouncyCastle", () -> {
      it("should ignore a null exception", () -> {
        BCNullConnection connection = new BCNullConnection();
        connection.reconnect(null);
        // passes
      });

      it("should rethrow a real exception", () -> {
        BCNullConnection connection = new BCNullConnection();
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
