package org.cloudfoundry.credhub.utils

import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException
import org.junit.Test
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class PrivateKeyReaderTest {

    @Test
    fun `getPrivateKey returns RSA format PrivateKey from PKCS1 string`() {
        val pkcs1String = TestConstants.TEST_PRIVATE_KEY
        val privateKey: PrivateKey = PrivateKeyReader.getPrivateKey(pkcs1String)
        assertThat(privateKey).isInstanceOf(RSAPrivateKey::class.java)
    }

    @Test
    fun `getPrivateKey returns RSA format PrivateKey from PKCS8 string`() {
        val pkcs8String = TestConstants.TEST_PRIVATE_KEY_PKCS8
        val privateKey: PrivateKey = PrivateKeyReader.getPrivateKey(pkcs8String)
        assertThat(privateKey).isInstanceOf(RSAPrivateKey::class.java)
    }

    @Test
    fun `getPrivateKey throws MalformedPrivateKeyException if not RSA format`() {
        val ecString = TestConstants.TEST_PRIVATE_KEY_EC
        Assertions.assertThatThrownBy {
            PrivateKeyReader.getPrivateKey(ecString)
        }.isInstanceOf(MalformedPrivateKeyException::class.java)
            .hasMessage("Key file does not contain an RSA private key")
    }

    @Test
    fun `getPrivateKey throws MalformedPrivateKeyException if not PKCS1 or unencrypted PKCS8 format`() {
        val encryptedPrivateKeyString = TestConstants.ENCRYPTED_TEST_PRIVATE_KEY_PKCS8
        Assertions.assertThatThrownBy {
            PrivateKeyReader.getPrivateKey(encryptedPrivateKeyString)
        }.isInstanceOf(MalformedPrivateKeyException::class.java)
            .hasMessage("Key file is not in PKCS#1 or unencrypted PKCS#8 format")
    }

    @Test
    fun `getPrivateKey throws MalformedPrivateKeyException if key is not valid`() {
        val encryptedPrivateKeyString = TestConstants.INVALID_PRIVATE_KEY_WITH_HEADERS
        Assertions.assertThatThrownBy {
            PrivateKeyReader.getPrivateKey(encryptedPrivateKeyString)
        }.isInstanceOf(MalformedPrivateKeyException::class.java)
            .hasMessage("Keys must be PEM-encoded PKCS#1 or unencrypted PKCS#8 keys.")
    }

    @Test
    fun `getPrivateKey throws MalformedPrivateKeyException if key is cannot be parsed`() {
        val encryptedPrivateKeyString = TestConstants.INVALID_PRIVATE_KEY_NO_HEADERS
        Assertions.assertThatThrownBy {
            PrivateKeyReader.getPrivateKey(encryptedPrivateKeyString)
        }.isInstanceOf(MalformedPrivateKeyException::class.java)
            .hasMessage("Key file is not in PKCS#1 or unencrypted PKCS#8 format")
    }

    @Test
    fun `getPublicKey returns RSA format PublicKey from valid(RSA formatted) Private Key`() {
        val pkcs1String = TestConstants.TEST_PRIVATE_KEY
        val publicKey: PublicKey = PrivateKeyReader.getPublicKey(pkcs1String)
        assertThat(publicKey).isInstanceOf(RSAPublicKey::class.java)
    }
}
