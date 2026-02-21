package org.cloudfoundry.credhub.utils

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.asn1.x509.KeyUsage
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.CRL_SIGN
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DATA_ENCIPHERMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DECIPHER_ONLY
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.DIGITAL_SIGNATURE
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.ENCIPHER_ONLY
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_AGREEMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_CERT_SIGN
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.KEY_ENCIPHERMENT
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.Companion.NON_REPUDIATION
import org.junit.jupiter.api.Test

class KeyUsageMapperTest {
    @Test
    fun `mapKeyUsage maps digital_signature correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(DIGITAL_SIGNATURE))
        assertThat(keyUsage.hasUsages(KeyUsage.digitalSignature)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps non_repudiation correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(NON_REPUDIATION))
        assertThat(keyUsage.hasUsages(KeyUsage.nonRepudiation)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps key_encipherment correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(KEY_ENCIPHERMENT))
        assertThat(keyUsage.hasUsages(KeyUsage.keyEncipherment)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps data_encipherment correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(DATA_ENCIPHERMENT))
        assertThat(keyUsage.hasUsages(KeyUsage.dataEncipherment)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps key_agreement correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(KEY_AGREEMENT))
        assertThat(keyUsage.hasUsages(KeyUsage.keyAgreement)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps key_cert_sign correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(KEY_CERT_SIGN))
        assertThat(keyUsage.hasUsages(KeyUsage.keyCertSign)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps crl_sign correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(CRL_SIGN))
        assertThat(keyUsage.hasUsages(KeyUsage.cRLSign)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps encipher_only correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(ENCIPHER_ONLY))
        assertThat(keyUsage.hasUsages(KeyUsage.encipherOnly)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps decipher_only correctly`() {
        val keyUsage = KeyUsageMapper.mapKeyUsage(arrayOf(DECIPHER_ONLY))
        assertThat(keyUsage.hasUsages(KeyUsage.decipherOnly)).isTrue()
    }

    @Test
    fun `mapKeyUsage maps multiple key usages correctly`() {
        val keyUsage =
            KeyUsageMapper.mapKeyUsage(
                arrayOf(DIGITAL_SIGNATURE, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT),
            )
        assertThat(keyUsage.hasUsages(KeyUsage.digitalSignature)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.keyEncipherment)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.dataEncipherment)).isTrue()
    }

    @Test
    fun `mapKeyUsage throws exception for invalid key usage`() {
        assertThatThrownBy {
            KeyUsageMapper.mapKeyUsage(arrayOf("invalid_usage"))
        }.isInstanceOf(ParameterizedValidationException::class.java)
            .hasFieldOrPropertyWithValue("message", ErrorMessages.INVALID_KEY_USAGE)
    }

    @Test
    fun `mapKeyUsage handles all key usages at once`() {
        val keyUsage =
            KeyUsageMapper.mapKeyUsage(
                arrayOf(
                    DIGITAL_SIGNATURE,
                    NON_REPUDIATION,
                    KEY_ENCIPHERMENT,
                    DATA_ENCIPHERMENT,
                    KEY_AGREEMENT,
                    KEY_CERT_SIGN,
                    CRL_SIGN,
                    ENCIPHER_ONLY,
                    DECIPHER_ONLY,
                ),
            )
        assertThat(keyUsage.hasUsages(KeyUsage.digitalSignature)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.nonRepudiation)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.keyEncipherment)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.dataEncipherment)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.keyAgreement)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.keyCertSign)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.cRLSign)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.encipherOnly)).isTrue()
        assertThat(keyUsage.hasUsages(KeyUsage.decipherOnly)).isTrue()
    }
}
