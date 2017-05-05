package io.pivotal.security.domain;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class SshCredentialTest {

  private SshCredential subject;
  private Encryptor encryptor;

  {
    beforeEach(() -> {
      encryptor = mock(Encryptor.class);
      subject = new SshCredential("/Foo");
    });

    it("returns type ssh", () -> {
      assertThat(subject.getCredentialType(), equalTo("ssh"));
    });
  }
}
