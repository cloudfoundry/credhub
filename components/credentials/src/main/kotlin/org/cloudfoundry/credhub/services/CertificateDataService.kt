package org.cloudfoundry.credhub.services

import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.domain.CertificateMetadata
import org.cloudfoundry.credhub.domain.CertificateVersionMetadata
import org.cloudfoundry.credhub.entity.Credential
import org.cloudfoundry.credhub.repositories.CredentialRepository
import org.intellij.lang.annotations.Language
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import java.nio.ByteBuffer
import java.sql.Timestamp
import java.util.UUID

@Service
class CertificateDataService @Autowired
constructor(
    private val credentialRepository: CredentialRepository,
    private val auditRecord: CEFAuditRecord,
    private val jdbcTemplate: JdbcTemplate
) {

    fun findAll(): List<Credential> {
        return credentialRepository.findAllCertificates()
    }

    fun findByName(name: String): Credential? {
        val credential = credentialRepository.findCertificateByName(name)
        auditRecord.setResource(credential)
        return credential
    }

    fun findByUuid(uuid: UUID): Credential? {
        return credentialRepository.findCertificateByUuid(uuid)
    }

    fun findAllValidMetadata(names: List<String>): List<CertificateMetadata> {
        val nameSet = names.toHashSet()
        val certificateMetadataMap = mutableMapOf<UUID, CertificateMetadata>()

        @Language("GenericSQL")
        val query = """
            select
              certificate_credential.uuid as VERSION_UUID,
              credential.name as NAME,
              credential.uuid as CREDENTIAL_UUID,
              certificate_credential.ca_name as CA_NAME,
              certificate_credential.expiry_date as EXPIRY_DATE,
              certificate_credential.transitional as TRANSITIONAL,
              certificate_credential.certificate_authority as CERTIFICATE_AUTHORITY,
              certificate_credential.self_signed as SELF_SIGNED,
              certificate_credential.generated as GENERATED
            from certificate_credential
            inner join credential_version on certificate_credential.uuid = credential_version.uuid
            inner join credential on credential_version.credential_uuid = credential.uuid
            order by credential_version.version_created_at desc
        """.trimIndent()

        val rowSet = jdbcTemplate.queryForRowSet(query)
        while (rowSet.next()) {
            val name = rowSet.getString("NAME")
            val expiryDate = rowSet.getObject("EXPIRY_DATE") as Timestamp
            if (nameSet.contains(name)) {
                val isSelfSigned = rowSet.getBoolean("SELF_SIGNED")
                val isCertificateAuthority = rowSet.getBoolean("CERTIFICATE_AUTHORITY")
                val isGenerated = rowSet.getObject("GENERATED") as? Boolean

                val certificateVersionMetadata = CertificateVersionMetadata(
                    toUUID(rowSet.getObject("VERSION_UUID")),
                    expiryDate.toInstant(),
                    rowSet.getBoolean("TRANSITIONAL"),
                    isCertificateAuthority,
                    isSelfSigned,
                    isGenerated
                )

                val credentialUUID: UUID = toUUID(rowSet.getObject("CREDENTIAL_UUID"))

                if (certificateMetadataMap.containsKey(credentialUUID)) {
                    certificateMetadataMap.getValue(credentialUUID).versions.add(certificateVersionMetadata)
                } else {
                    val caName = if (isSelfSigned) name else rowSet.getString("CA_NAME")

                    val certificateMetadata = CertificateMetadata(
                        credentialUUID,
                        name,
                        caName,
                        mutableListOf(certificateVersionMetadata)
                    )
                    certificateMetadataMap[credentialUUID] = certificateMetadata
                }
            }
        }

        return certificateMetadataMap.values.toList()
    }

    private fun toUUID(o: Any): UUID {
        return when {
            o.javaClass == ByteArray::class.java -> {
                val bytes = o as ByteArray
                if (bytes.size != 16) {
                    throw IllegalArgumentException("Expected byte[] of length 16. Received length " + bytes.size)
                }
                val byteBuffer = ByteBuffer.wrap(bytes)
                val high = byteBuffer.long
                val low = byteBuffer.long

                UUID(high, low)
            }
            o.javaClass == UUID::class.java -> o as UUID
            else -> throw IllegalArgumentException("Expected byte[] or UUID type. Received " + o.javaClass.toString())
        }
    }
}
