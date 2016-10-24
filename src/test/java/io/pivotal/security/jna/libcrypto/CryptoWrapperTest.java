package io.pivotal.security.jna.libcrypto;

import com.greghaskins.spectrum.Spectrum;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.jna.libcrypto.Crypto.RSA_NO_PADDING;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import javax.crypto.Cipher;

@RunWith(Spectrum.class)
public class CryptoWrapperTest {

  private CryptoWrapper subject;

  private final BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

  {
    beforeEach(() -> {
      Security.addProvider(bouncyCastleProvider);
      subject = new CryptoWrapper(bouncyCastleProvider);
    });

    it("can generate keypairs", () -> {
      subject.generateKeyPair(1024, first -> {
        KeyPair firstKeyPair = subject.toKeyPair(first);
        assertThat(firstKeyPair.getPublic(), notNullValue());

        assertThat("The first key should not repeat (RNG has been seeded)", firstKeyPair.getPublic().getEncoded(), not(equalTo(new byte[] {
            48, -127, -97, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1,
            5, 0, 3, -127, -115, 0, 48, -127, -119, 2, -127, -127, 0, -81, -49, -46,
            -34, 69, 68, 5, 24, -79, -93, -127, 46, -19, -11, 82, 65, -109, 117, -4,
            -124, 114, -37, 78, -54, -51, -5, 111, 39, -93, 91, -24, -113, -121, 12, -109,
            -101, -89, 38, -53, 125, -57, 85, -55, 28, 75, 7, -61, 58, 70, 103, 115,
            73, 63, 114, 25, -70, 29, 65, -105, 43, -35, 39, -85, -71, -93, -37, -1,
            95, -55, 118, 69, 76, 70, 37, 82, -98, 82, -127, 80, -32, 80, -4, 30, -121,
            -104, 88, 22, -52, 126, -52, 83, 58, 77, -11, 114, -79, 109, -91, 25, 51,
            -97, 14, 22, -30, 21, -76, -32, -83, -82, -97, -86, 102, -5, -26, 116, 122,
            -33, -73, -80, -123, 31, 50, -119, -8, -89, 12, -72, -65, 2, 3, 1, 0, 1
        })));

        subject.generateKeyPair(1024, second -> {
          KeyPair secondKeyPair = subject.toKeyPair(second);
          assertThat(secondKeyPair.getPublic(), notNullValue());

          assertThat(secondKeyPair.getPublic().getEncoded(), not(equalTo(firstKeyPair.getPublic().getEncoded())));
        });
      });
    });

    it("can transform RSA structs into KeyPairs", () -> {
      subject.generateKeyPair(1024, rsa -> {
        byte[] plaintext = new byte[128];
        byte[] message = "OpenSSL for speed".getBytes();
        System.arraycopy(message, 0, plaintext, 0, message.length);

        byte[] ciphertext = new byte[Crypto.RSA_size(rsa)];
        int result = Crypto.RSA_private_encrypt(plaintext.length, plaintext, ciphertext, rsa, RSA_NO_PADDING);
        if (result == -1) {
          byte[] buffer = new byte[128];
          Crypto.ERR_error_string_n(Crypto.ERR_get_error(), buffer, buffer.length);
          System.out.println(new String(buffer));
        }
        assert result >= 0;

        KeyPair keyPair = subject.toKeyPair(rsa);
        PrivateKey privateKey = keyPair.getPrivate();

        Cipher cipher = Cipher.getInstance(CryptoWrapper.ALGORITHM, bouncyCastleProvider);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] javaCipherText = cipher.doFinal(plaintext);

        assertThat("Encryption should work the same inside and outside openssl", javaCipherText, equalTo(ciphertext));
      });
    });
  }
}
