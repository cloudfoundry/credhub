package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.entities.Credential
import org.cloudfoundry.credhub.repositories.CredentialRepository
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.CoreMatchers
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.hamcrest.core.IsEqual
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@RunWith(SpringRunner::class)
@ActiveProfiles(value = ["unit-test"], resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
@Transactional
class CredentialDataServiceTest {
    @Autowired
    private val subject: CredentialDataService? = null
    @Autowired
    private val credentialRepository: CredentialRepository? = null
    @Autowired
    private val auditRecord: CEFAuditRecord? = null

    @Test
    fun save_savesTheCredential() {
        val credential = Credential(CREDENTIAL_NAME)
        MatcherAssert.assertThat(credentialRepository!!.count(), IsEqual.equalTo(0L))
        credentialRepository.save(credential)
        MatcherAssert.assertThat(credentialRepository.count(), IsEqual.equalTo(1L))
        MatcherAssert.assertThat(
            credentialRepository.findOneByNameIgnoreCase(CREDENTIAL_NAME)!!.name,
            IsEqual.equalTo(CREDENTIAL_NAME)
        )
    }

    @Test
    fun save_setsTheUuidOnTheCredential() {
        val credential = credentialRepository!!.save(Credential(CREDENTIAL_NAME))
        MatcherAssert.assertThat(credential.uuid, CoreMatchers.instanceOf(UUID::class.java))
    }

    @Test
    fun find_whenTheCredentialExists_returnsTheCredential() {
        val credential = Credential(CREDENTIAL_NAME)
        credentialRepository!!.save(credential)
        MatcherAssert.assertThat(subject!!.find(CREDENTIAL_NAME), IsEqual.equalTo(credential))
    }

    @Test
    fun find_isCaseInsensitive() {
        val credential = Credential(CREDENTIAL_NAME.lowercase())
        credentialRepository!!.save(credential)
        MatcherAssert.assertThat(subject!!.find(CREDENTIAL_NAME.uppercase()), IsEqual.equalTo(credential))
    }

    @Test
    fun find_whenTheCredentialDoesNotExist_returnsNull() {
        MatcherAssert.assertThat(subject!!.find(CREDENTIAL_NAME), IsEqual.equalTo<Credential?>(null))
    }

    @Test
    fun findByUUID_whenTheCredentialExists_returnsTheCredential() {
        val credential = Credential(CREDENTIAL_NAME)
        credentialRepository!!.save(credential)
        MatcherAssert.assertThat(subject!!.findByUUID(credential.uuid), IsEqual.equalTo(credential))
    }

    @Test
    fun delete_whenTheCredentialExists_deletesTheCredential_andReturnsTrue() {
        credentialRepository!!.save(Credential(CREDENTIAL_NAME))
        MatcherAssert.assertThat(subject!!.delete(CREDENTIAL_NAME), IsEqual.equalTo(true))
        MatcherAssert.assertThat(credentialRepository.count(), IsEqual.equalTo(0L))
    }

    @Test
    fun delete_addsToAuditRecord() {
        credentialRepository!!.save(Credential(CREDENTIAL_NAME))
        MatcherAssert.assertThat(subject!!.delete(CREDENTIAL_NAME), IsEqual.equalTo(true))
        MatcherAssert.assertThat(auditRecord!!.resourceName, Matchers.`is`(CREDENTIAL_NAME))
    }

    @Test
    fun delete_whenTheCredentialDoesNotExist_returnsFalse() {
        MatcherAssert.assertThat(subject!!.delete(CREDENTIAL_NAME), IsEqual.equalTo(false))
    }

    @Test
    fun delete_isCaseInsensitive() {
        credentialRepository!!.save(Credential(CREDENTIAL_NAME.uppercase()))
        MatcherAssert.assertThat(subject!!.delete(CREDENTIAL_NAME.lowercase()), IsEqual.equalTo(true))
        MatcherAssert.assertThat(credentialRepository.count(), IsEqual.equalTo(0L))
    }

    companion object {
        private const val CREDENTIAL_NAME = "/test/credential"
    }
}
