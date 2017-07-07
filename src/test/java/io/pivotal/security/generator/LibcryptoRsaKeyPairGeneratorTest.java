package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.jna.libcrypto.CryptoWrapper;
import io.pivotal.security.service.BcEncryptionService;
import io.pivotal.security.service.PasswordKeyProxyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import java.security.KeyPair;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class LibcryptoRsaKeyPairGeneratorTest {

  private LibcryptoRsaKeyPairGenerator subject;

  {
    beforeEach(() -> {
      BouncyCastleProvider bouncyCastleProvider = getBouncyCastleProvider();
      BcEncryptionService encryptionService = new BcEncryptionService(bouncyCastleProvider, mock(PasswordKeyProxyFactory.class));
      subject = new LibcryptoRsaKeyPairGenerator(new CryptoWrapper(bouncyCastleProvider, encryptionService));
    });

    it("can generate keypairs", () -> {
      KeyPair keyPair = subject.generateKeyPair(2048);
      assertThat(keyPair.getPublic(), notNullValue());
      assertThat(keyPair.getPrivate(), notNullValue());
    });
  }
}
