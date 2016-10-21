package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.security.KeyPair;

@RunWith(Spectrum.class)
public class LibcryptoRsaKeyPairGeneratorTest {

  private LibcryptoRsaKeyPairGenerator subject;

  {
    beforeEach(() -> {
      subject = new LibcryptoRsaKeyPairGenerator(new BouncyCastleProvider());
    });

    it("can generate keypairs", () -> {
      KeyPair keyPair = subject.generateKeyPair(2048);
      assertThat(keyPair.getPublic(), notNullValue());
      assertThat(keyPair.getPrivate(), notNullValue());
    });
  }
}
