package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.AccessControlEntry;
import org.junit.runner.RunWith;

import java.util.ArrayList;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
public class AccessEntryDataTest {

  {
    describe("#getActor", () -> {
      it("should return the name of the actor", () -> {
        assertThat(new AccessEntryData(new CredentialName("test/name"), "ryan_gosling",
            new ArrayList<>()).getActor(), equalTo("ryan_gosling"));
      });
    });

    describe(".fromCredentialName", () -> {
      it("should return and AccessEntryData with the correct CredentialName and ACE details", () -> {
        CredentialName credentialName = new CredentialName("test/name");
        AccessEntryData entryData = AccessEntryData.fromCredentialName(credentialName,
            new AccessControlEntry("ryan_gosling", new ArrayList<>()));
        assertThat(entryData.getActor(), equalTo("ryan_gosling"));
        assertThat(entryData.getCredentialName(), equalTo(credentialName));
      });
    });
  }

}
