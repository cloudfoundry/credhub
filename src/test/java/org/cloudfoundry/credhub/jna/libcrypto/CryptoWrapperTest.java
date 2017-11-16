package org.cloudfoundry.credhub.jna.libcrypto;

import com.sun.jna.Pointer;
import org.cloudfoundry.credhub.service.InternalEncryptionService;
import org.cloudfoundry.credhub.service.PasswordKeyProxyFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;

import static org.cloudfoundry.credhub.jna.libcrypto.Crypto.RSA_PKCS1_PADDING;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(JUnit4.class)
public class CryptoWrapperTest {

  private CryptoWrapper subject;

  @Before
  public void beforeEach() throws Exception {
    InternalEncryptionService encryptionService = new InternalEncryptionService(mock(PasswordKeyProxyFactory.class));

    subject = new CryptoWrapper(encryptionService);
  }

  @Test
  public void generateKeyPair_generatesKeyPairs() throws InvalidKeySpecException {
    // We expect that the openssl random number generator is seeded automatically.
    // RSA_generate_key_ex uses BN_generate_prime for primes
    // BN_generate_prime uses RAND, and RAND is transparently seeded with /dev/urandom

    // https://www.openssl.org/docs/man1.0.1/crypto/RSA_generate_key.html
    // https://www.openssl.org/docs/man1.0.1/crypto/BN_generate_prime.html
    // https://www.openssl.org/docs/man1.0.1/crypto/RAND_add.html

    subject.generateKeyPair(1024, first -> {
      KeyPair firstKeyPair = subject.toKeyPair(first);
      assertThat(firstKeyPair.getPublic(), notNullValue());

      subject.generateKeyPair(1024, second -> {
        KeyPair secondKeyPair = subject.toKeyPair(second);
        assertThat(secondKeyPair.getPublic(), notNullValue());

        assertThat(secondKeyPair.getPublic().getEncoded(),
            not(equalTo(firstKeyPair.getPublic().getEncoded())));
      });
    });
  }

  @Test
  public void canTransformRsaStructsIntoKeyPairs() throws GeneralSecurityException {
    subject.generateKeyPair(1024, rsa -> {
      byte[] plaintext = new byte[117];
      byte[] message = "OpenSSL for speed".getBytes();
      System.arraycopy(message, 0, plaintext, 0, message.length);

      byte[] ciphertext = new byte[Crypto.RSA_size(rsa)];
      int result = Crypto
          .RSA_private_encrypt(plaintext.length, plaintext, ciphertext, rsa, RSA_PKCS1_PADDING);
      if (result == -1) {
        System.out.println(subject.getError());
      }
      assert result >= 0;

      KeyPair keyPair = subject.toKeyPair(rsa);
      PrivateKey privateKey = keyPair.getPrivate();

      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      byte[] javaCipherText = cipher.doFinal(plaintext);

      assertThat("Encryption should work the same inside and outside openssl", javaCipherText,
          equalTo(ciphertext));
    });
  }

  @Test(expected = IllegalArgumentException.class)
  public void generateKeyPair_withHugeKeySize_throwsException() {
    // https://crypto.stackexchange.com/a/1184/7763
    subject.generateKeyPair(1024 * 16, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void generateKeyPair_withSmallKeySize_throwsException() {
    subject.generateKeyPair(512, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void convert_withNullPointer_throwsException() {
    subject.convert(Pointer.NULL);
  }

  @Test
  public void convertingBignumToBigInteger_worksForSmallPositiveNumbers() {
    Pointer bn = Crypto.BN_new();
    try {
      Crypto.BN_set_word(bn, 18);
      BigInteger converted = subject.convert(bn);
      Pointer hex = Crypto.BN_bn2hex(bn);
      try {
        assertThat(hex.getString(0), equalTo("12"));
        assertThat(converted.toString(16).toUpperCase(), equalTo(hex.getString(0)));
      } finally {
        Crypto.CRYPTO_free(hex);
      }
    } finally {
      Crypto.BN_free(bn);
    }
  }

  @Test
  public void convertingBignumToBigInteger_worksForSmallNegativeNumbers() {
    Pointer bn = Crypto.BN_new();
    try {
      Crypto.BN_set_word(bn, 16);
      Crypto.BN_set_negative(bn, 1);
      BigInteger converted = subject.convert(bn);
      Pointer hex = Crypto.BN_bn2hex(bn);
      try {
        assertThat(hex.getString(0), equalTo("-10"));
        assertThat(converted.toString(16).toUpperCase(), equalTo(hex.getString(0)));
      } finally {
        Crypto.CRYPTO_free(hex);
      }
    } finally {
      Crypto.BN_free(bn);
    }
  }

  @Test
  public void convertingBignumToBigInteger_worksWithMoreThan64Bits() {
    Pointer bn = Crypto.BN_new();
    try {
      Crypto.BN_set_word(bn, 0x1234567800000000L);
      Crypto.BN_mul_word(bn, 0xFFFFFFFFFFFFFFFFL);
      BigInteger converted = subject.convert(bn);
      Pointer hex = Crypto.BN_bn2hex(bn);
      try {
        assertThat(hex.getString(0), equalTo("12345677FFFFFFFFEDCBA98800000000"));
        assertThat(converted.toString(16).toUpperCase(), equalTo(hex.getString(0)));
      } finally {
        Crypto.CRYPTO_free(hex);
      }
    } finally {
      Crypto.BN_free(bn);
    }
  }
}
