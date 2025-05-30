package org.cloudfoundry.credhub.repositories

import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.entities.EncryptedValue
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.MatcherAssert
import org.hamcrest.core.IsEqual
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.UUID
import java.util.stream.Stream

@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@SpringBootTest(classes = [CredhubTestApp::class])
class CredentialVersionDataRepositoryTest {
    @Autowired
    private val subject: CredentialVersionRepository? = null

    @Autowired
    private val credentialRepository: CredentialRepository? = null

    @Autowired
    private val canaryRepository: EncryptionKeyCanaryRepository? = null
    private var name: String? = null
    private var canaryUuid: UUID? = null

    @BeforeEach
    fun beforeEach() {
        name = "my-credential"
        val canary = canaryRepository!!.save(EncryptionKeyCanary())
        canaryUuid = canary.uuid
    }

    @AfterEach
    fun tearDown() {
        credentialRepository!!.deleteAll()
    }

    @Test
    fun canSaveCertificatesOfLength7000WhichMeans7016ForGCM() {
        val encryptedValue = ByteArray(7016)
        Arrays.fill(encryptedValue, 'A'.code.toByte())
        val stringBuilder = StringBuilder(7000)
        Stream.generate { "a" }.limit(stringBuilder.capacity().toLong()).forEach { str: String? -> stringBuilder.append(str) }
        val credential = credentialRepository!!.save(Credential(name))
        val longString = stringBuilder.toString()
        val entityEncryptedValue = EncryptedValue()
        entityEncryptedValue.encryptionKeyUuid = canaryUuid
        entityEncryptedValue.encryptedValue = encryptedValue
        entityEncryptedValue.nonce = "nonce".toByteArray(StandardCharsets.UTF_8)
        val entity = CertificateCredentialVersionData("test-ca")
        entity.credential = credential
        entity.ca = longString
        entity.certificate = longString
        entity.setEncryptedValueData(entityEncryptedValue)
        subject!!.save(entity)
        val credentialData =
            subject
                .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.uuid) as CertificateCredentialVersionData?
        MatcherAssert.assertThat(credentialData!!.ca!!.length, IsEqual.equalTo(7000))
        MatcherAssert.assertThat(credentialData.certificate!!.length, IsEqual.equalTo(7000))
        MatcherAssert.assertThat(credentialData.getEncryptedValueData()!!.encryptedValue, IsEqual.equalTo(encryptedValue))
        MatcherAssert.assertThat(credentialData.getEncryptedValueData()!!.encryptedValue.size, IsEqual.equalTo(7016))
    }

    @Test
    fun canSaveStringsOfLength7000WhichMeans7016ForGCM() {
        val encryptedValue = ByteArray(7016)
        Arrays.fill(encryptedValue, 'A'.code.toByte())
        val stringBuilder = StringBuilder(7000)
        Stream.generate { "a" }.limit(stringBuilder.capacity().toLong()).forEach { str: String? -> stringBuilder.append(str) }
        val entity = ValueCredentialVersionData("test-credential")
        val entityEncryptedValue = EncryptedValue()
        entityEncryptedValue.encryptedValue = encryptedValue
        entityEncryptedValue.encryptionKeyUuid = canaryUuid
        entityEncryptedValue.nonce = "nonce".toByteArray(StandardCharsets.UTF_8)
        val credential = credentialRepository!!.save(Credential(name))
        entity.credential = credential
        entity.setEncryptedValueData(entityEncryptedValue)
        subject!!.save(entity)
        val encryptedValueData = subject.findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.uuid)!!.getEncryptedValueData()!!
        MatcherAssert.assertThat(encryptedValueData.encryptedValue.size, IsEqual.equalTo(7016))
    }
}
