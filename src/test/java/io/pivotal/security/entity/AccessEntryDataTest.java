package io.pivotal.security.entity;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.AccessControlEntry;
import java.util.ArrayList;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class AccessEntryDataTest {

  {
    describe("#getActor", () -> {
      it("should return the name of the actor", () -> {
        assertThat(new AccessEntryData(new SecretName("test/name"), "ryan_gosling",
            new ArrayList<>()).getActor(), equalTo("ryan_gosling"));
      });
    });

    describe(".fromSecretName", () -> {
      it("should return and AccessEntryData with the correct SecretName and ACE details", () -> {
        SecretName secretName = new SecretName("test/name");
        AccessEntryData entryData = AccessEntryData.fromSecretName(secretName,
            new AccessControlEntry("ryan_gosling", new ArrayList<>()));
        assertThat(entryData.getActor(), equalTo("ryan_gosling"));
        assertThat(entryData.getCredentialName(), equalTo(secretName));
      });
    });
  }

}