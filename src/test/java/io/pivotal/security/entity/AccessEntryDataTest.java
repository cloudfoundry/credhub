package io.pivotal.security.entity;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import com.greghaskins.spectrum.Spectrum;
import java.util.ArrayList;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class AccessEntryDataTest {

  {
    describe("#getActor", () -> {
      it("should return the name of the actor", () -> {
        assertThat(new AccessEntryData(new CredentialName("test/name"), "ryan_gosling",
            new ArrayList<>()).getActor(), equalTo("ryan_gosling"));
      });
    });
  }

}
