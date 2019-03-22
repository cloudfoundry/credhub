package org.cloudfoundry.credhub.validators

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException
import org.cloudfoundry.credhub.utils.TestConstants
import org.junit.Before
import org.junit.Test
import java.security.Security

class CertificateMatchesPrivateKeyValidatorTest {

    @Before
    fun beforeEach() {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleFipsProvider())
        }
    }

    @Test
    fun `isValid should return false when PKCS1 key does not match cert`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()
        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.OTHER_TEST_PRIVATE_KEY,
            "some ca name"
        )

        val valid = certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        assertThat(valid).isFalse()
    }

    @Test
    fun `isValid should return true when PKCS1 key matches cert`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()
        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY,
            "some ca name"
        )

        val valid = certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        assertThat(valid).isTrue()
    }

    @Test
    fun `isValid should return false when PKCS8 key does not match cert`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()
        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.OTHER_TEST_PRIVATE_KEY_PKCS8,
            "some ca name"
        )

        val valid = certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        assertThat(valid).isFalse()
    }

    @Test
    fun `isValid should return true when PKCS8 key matches cert`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()
        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.TEST_PRIVATE_KEY_PKCS8,
            "some ca name"
        )

        val valid = certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        assertThat(valid).isTrue()
    }

    @Test
    fun `isValid should throw a MalformedPrivateKeyException when PrivateKey is malformed`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()

        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            TestConstants.INVALID_PRIVATE_KEY_NO_HEADERS,
            "some ca name"
        )

        assertThatThrownBy {
            certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        }.isInstanceOf(MalformedPrivateKeyException::class.java)
    }

    @Test
    fun `isValid should return true when certificate or ca is null or empty`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()

        val certificateCredentialValue = CertificateCredentialValue(
            null,
            "",
            TestConstants.TEST_PRIVATE_KEY,
            "some ca name"
        )

        val valid = certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        assertThat(valid).isTrue()
    }

    @Test
    fun `isValid should return true when private key is null or empty`() {
        val certificateMatchesPrivateKeyValidator = CertificateMatchesPrivateKeyValidator()

        val certificateCredentialValue = CertificateCredentialValue(
            TestConstants.TEST_CA,
            TestConstants.TEST_CERTIFICATE,
            "",
            "some ca name"
        )

        val valid = certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null)
        assertThat(valid).isTrue()
    }
}
