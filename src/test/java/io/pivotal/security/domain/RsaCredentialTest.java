package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class RsaCredentialTest {

  private RsaCredential subject;
  private Encryptor encryptor;
  private UUID canaryUuid;

  {
    beforeEach(() -> {
      canaryUuid = UUID.randomUUID();
      encryptor = mock(Encryptor.class);
      subject = new RsaCredential("/Foo");
    });

    it("returns type rsa", () -> {
      assertThat(subject.getCredentialType(), equalTo("rsa"));
    });
  }
}
