package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class SecretNameTest {
  {
    describe("#getName", () -> {
      describe("when the original name is prepended with a '/'", () -> {
        it("should return the original name as-is", () -> {
          assertThat(new SecretName("/foo/bar").getName(), equalTo("/foo/bar"));
        });
      });

      describe("when the original name was not prepended wiht a '/'", () -> {
        it("should prepend a '/' to the original name", () -> {
          assertThat(new SecretName("foo/bar").getName(), equalTo("/foo/bar"));
        });
      });
    });
  }
}
