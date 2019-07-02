package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.repositories.CredentialRepository
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.anyString
import org.mockito.Mockito.mock
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.support.rowset.SqlRowSet
import java.sql.Timestamp
import java.time.Instant
import java.util.UUID

class CertificateDataServiceTest {

    private lateinit var jdbcTemplate: JdbcTemplate
    private lateinit var subject: CertificateDataService
    private lateinit var auditRecord: CEFAuditRecord
    private lateinit var credentialRepository: CredentialRepository

    @Before
    fun beforeEach() {
        jdbcTemplate = mock(JdbcTemplate::class.java)
        auditRecord = mock(CEFAuditRecord::class.java)
        credentialRepository = mock(CredentialRepository::class.java)
        subject = CertificateDataService(credentialRepository, auditRecord, jdbcTemplate)
    }

    @Test
    fun `find all valid metadata when user has permissions returns certificates`() {
        val permissions = listOf("cert")
        val rowSet = mock(SqlRowSet::class.java)
        val versionUuid = UUID.randomUUID()
        val credentialUuid = UUID.randomUUID()
        val expectedExpiryDate = Instant.now()

        `when`(jdbcTemplate.queryForRowSet(anyString())).thenReturn(rowSet)
        `when`(rowSet.next()).thenReturn(true).thenReturn(false)
        `when`(rowSet.getString("NAME")).thenReturn("cert")
        `when`(rowSet.getObject("VERSION_UUID")).thenReturn(versionUuid)
        `when`(rowSet.getObject("EXPIRY_DATE")).thenReturn(Timestamp.from(expectedExpiryDate))
        `when`(rowSet.getBoolean("TRANSITIONAL")).thenReturn(false)
        `when`(rowSet.getObject("CREDENTIAL_UUID")).thenReturn(credentialUuid)
        `when`(rowSet.getString("CA_NAME")).thenReturn("some-ca")
        `when`(rowSet.getBoolean("CERTIFICATE_AUTHORITY")).thenReturn(false)
        `when`(rowSet.getBoolean("SELF_SIGNED")).thenReturn(false)
        `when`(rowSet.getObject("GENERATED")).thenReturn(true)

        val result = subject.findAllValidMetadata(permissions)

        assertEquals(1, result.size)
        assertEquals("cert", result[0].name)
        assertEquals(versionUuid, result[0].versions[0].id)
        assertEquals(credentialUuid, result[0].id)
        assertEquals("some-ca", result[0].caName)
        assertEquals(false, result[0].versions[0].isTransitional)
        assertEquals(expectedExpiryDate, result[0].versions[0].expiryDate)
        assertEquals(false, result[0].versions[0].isCertificateAuthority)
        assertEquals(false, result[0].versions[0].isSelfSigned)
        assertEquals(true, result[0].versions[0].generated)
    }

    @Test
    fun `find all valid metadata when user does not have permissions returns empty list`() {
        val permissions = emptyList<String>()
        val rowSet = mock(SqlRowSet::class.java)
        val versionUuid = UUID.randomUUID()
        val credentialUuid = UUID.randomUUID()
        val expectedExpiryDate = Instant.now()

        `when`(jdbcTemplate.queryForRowSet(anyString())).thenReturn(rowSet)
        `when`(rowSet.next()).thenReturn(true).thenReturn(false)
        `when`(rowSet.getString("NAME")).thenReturn("cert")
        `when`(rowSet.getObject("VERSION_UUID")).thenReturn(versionUuid)
        `when`(rowSet.getObject("EXPIRY_DATE")).thenReturn(Timestamp.from(expectedExpiryDate))
        `when`(rowSet.getBoolean("TRANSITIONAL")).thenReturn(false)
        `when`(rowSet.getObject("CREDENTIAL_UUID")).thenReturn(credentialUuid)
        `when`(rowSet.getString("CA_NAME")).thenReturn("some-ca")
        `when`(rowSet.getBoolean("CERTIFICATE_AUTHORITY")).thenReturn(false)
        `when`(rowSet.getBoolean("SELF_SIGNED")).thenReturn(false)
        `when`(rowSet.getBoolean("GENERATED")).thenReturn(false)

        val result = subject.findAllValidMetadata(permissions)

        assertEquals(0, result.size)
    }
}
