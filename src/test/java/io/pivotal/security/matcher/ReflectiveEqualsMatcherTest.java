package io.pivotal.security.matcher;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.model.StringSecret;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class ReflectiveEqualsMatcherTest {
  {
    describe("a test for the matcher, which if fails, probably means the matcher is wrong, and not the setup", () -> {
      it("matches reflectively", () -> {
        StringSecret stringSecret = new StringSecret("something");

        assertThat(stringSecret, reflectiveEqualTo(stringSecret));

        StringSecret otherStringSecret = new StringSecret("something");
        assertThat(stringSecret, reflectiveEqualTo(otherStringSecret));

        otherStringSecret.setValue("something-else");
        assertThat(stringSecret, not(reflectiveEqualTo(otherStringSecret)));
      });
    });
  }
}