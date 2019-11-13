package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.Credential
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
class CertificateDataServiceTest {
    @Autowired
    private lateinit var subject: CertificateDataService

    @Autowired
    private lateinit var credentialDataService: CredentialDataService

    @Autowired
    private lateinit var credentialVersionDataService: CredentialVersionDataService

    @Test
    fun `findAllValidMetadata when certificate is in 'names' returns certificates`() {
        val name = "some-credential"
        val caName = "/some-ca"
        val otherName = "some-other-credential"
        val otherCaName = "/some-other-ca"
        val expectedExpiryDate = Instant.now()
        val certificateCredentialVersionData = CertificateCredentialVersionData(name)
        val otherCertificateCredentialVersionData = CertificateCredentialVersionData(otherName)
        certificateCredentialVersionData.caName = caName
        certificateCredentialVersionData.isTransitional = false
        certificateCredentialVersionData.expiryDate = expectedExpiryDate
        certificateCredentialVersionData.isCertificateAuthority = false
        certificateCredentialVersionData.isSelfSigned = false
        certificateCredentialVersionData.generated = true
        otherCertificateCredentialVersionData.caName = otherCaName
        otherCertificateCredentialVersionData.isTransitional = false
        otherCertificateCredentialVersionData.isCertificateAuthority = false
        otherCertificateCredentialVersionData.isSelfSigned = false
        otherCertificateCredentialVersionData.generated = true

        val certificateCredentialVersion = CertificateCredentialVersion(certificateCredentialVersionData)
        val otherCertificateCredentialVersion = CertificateCredentialVersion(otherCertificateCredentialVersionData)
        credentialVersionDataService.save(certificateCredentialVersion)
        credentialVersionDataService.save(otherCertificateCredentialVersion)

        val result = subject.findAllValidMetadata(listOf(name))

        assertEquals(1, result.size)
        assertEquals(name, result[0].name)
        assertEquals(caName, result[0].caName)
        assertEquals(false, result[0].versions[0].isTransitional)
        assertEquals(expectedExpiryDate, result[0].versions[0].expiryDate)
        assertEquals(false, result[0].versions[0].isCertificateAuthority)
        assertEquals(false, result[0].versions[0].isSelfSigned)
        assertEquals(true, result[0].versions[0].generated)
    }

    @Test
    fun `findAllValidMetadata returns certificate with null expiryDate when none exists`() {
        val name = "some-credential"
        val caName = "/some-ca"
        val certificateCredentialVersionData = CertificateCredentialVersionData(name)
        certificateCredentialVersionData.caName = caName
        certificateCredentialVersionData.isTransitional = false
        certificateCredentialVersionData.expiryDate = null
        certificateCredentialVersionData.isCertificateAuthority = false
        certificateCredentialVersionData.isSelfSigned = false
        certificateCredentialVersionData.generated = true

        val certificateCredentialVersion = CertificateCredentialVersion(certificateCredentialVersionData)
        credentialVersionDataService.save(certificateCredentialVersion)

        val result = subject.findAllValidMetadata(listOf(name))

        assertEquals(1, result.size)
        assertEquals(name, result[0].name)
        assertEquals(caName, result[0].caName)
        assertEquals(false, result[0].versions[0].isTransitional)
        assertEquals(null, result[0].versions[0].expiryDate)
        assertEquals(false, result[0].versions[0].isCertificateAuthority)
        assertEquals(false, result[0].versions[0].isSelfSigned)
        assertEquals(true, result[0].versions[0].generated)
    }

    @Test
    fun `findAllValidMetadata returns certificate versions in order by versionCreatedAt`() {
        val name = "some-credential"
        val caName = "some-ca"

        val credential = Credential(name)
        credentialDataService.save(credential)

        for (certificateVersion in 0..10) {
            val certificateCredentialVersionData = CertificateCredentialVersionData(name)
            certificateCredentialVersionData.expiryDate = Instant.now()
            certificateCredentialVersionData.credential = credential
            certificateCredentialVersionData.caName = caName
            credentialVersionDataService.save(certificateCredentialVersionData)
        }

        val result = subject.findAllValidMetadata(listOf(name))

        println("result = ${result[0].caName}")
        var previousExpiryDate = Instant.MAX
        for (credentialVersion in result[0].versions) {
            assertTrue(credentialVersion.expiryDate < previousExpiryDate)
            previousExpiryDate = credentialVersion.expiryDate
        }
    }

    @Test
    fun `findAllValidMetadata when certificate is not in 'names' returns empty list`() {
        val name = "some-credential"
        val certificateCredentialVersionData = CertificateCredentialVersionData(name)
        certificateCredentialVersionData.expiryDate = Instant.now()

        val certificateCredentialVersion = CertificateCredentialVersion(certificateCredentialVersionData)
        credentialVersionDataService.save(certificateCredentialVersion)

        val result = subject.findAllValidMetadata(emptyList())

        assertEquals(0, result.size)
    }
}
