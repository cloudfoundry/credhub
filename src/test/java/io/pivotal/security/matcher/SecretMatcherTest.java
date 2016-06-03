package io.pivotal.security.matcher;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.model.Secret;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.matcher.SecretMatcher.equalToSecret;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class SecretMatcherTest {
  {
    describe("a test for the matcher, which if fails, probably means the matcher is wrong, and not the setup", () -> {
      it("matches Secrets", () -> {
        Secret secret = new Secret();
        secret.type = "value";
        secret.value = "something";

        assertThat(secret, equalToSecret(secret));

        Secret otherSecret = new Secret();
        otherSecret.type = "value";
        otherSecret.value = "something";
        assertThat(secret, equalToSecret(otherSecret));

        otherSecret.value = "something-else";
        assertThat(secret, not(equalToSecret(otherSecret)));

        otherSecret.type = "ticket";
        assertThat(secret, not(equalToSecret(otherSecret)));

        otherSecret.value = "something";
        assertThat(secret, not(equalToSecret(otherSecret)));
      });
    });
  }
}