package org.cloudfoundry.credhub.services

import com.google.common.collect.Lists
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.domain.CredentialFactory
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.exceptions.MaximumSizeException
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository
import org.cloudfoundry.credhub.views.FindCertificateResult
import org.cloudfoundry.credhub.views.FindCredentialResult
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import java.sql.Timestamp
import java.time.Duration
import java.time.Instant
import java.util.HashMap
import java.util.UUID
import java.util.stream.Collectors
import kotlin.experimental.and

@Service
class DefaultCredentialVersionDataService @Autowired
constructor(
    private val credentialVersionRepository: CredentialVersionRepository,
    private val credentialDataService: CredentialDataService,
    private val jdbcTemplate: JdbcTemplate,
    private val credentialFactory: CredentialFactory,
    private val certificateVersionDataService: CertificateVersionDataService
) : CredentialVersionDataService {

    override fun save(credentialVersion: CredentialVersion): CredentialVersion {
        return credentialVersion.save<CredentialVersion>(this)
    }

    @SuppressFBWarnings(value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", justification = "Let's refactor this class into kotlin")
    override fun save(credentialVersionData: CredentialVersionData<*>): CredentialVersion {
        val credential = credentialVersionData.credential

        if (credential.uuid == null) {
            credentialVersionData.setCredential(credentialDataService.save(credential))
        } else {
            val existingCredentialVersion = findMostRecent(credential.name!!)
            if ((existingCredentialVersion != null && existingCredentialVersion.credentialType != credentialVersionData.credentialType)) {
                throw ParameterizedValidationException(ErrorMessages.TYPE_MISMATCH)
            }
        }

        return try {
            credentialFactory
                .makeCredentialFromEntity(credentialVersionRepository.saveAndFlush(credentialVersionData))
        } catch (e: DataIntegrityViolationException) {
            throw MaximumSizeException(e.message!!)
        }
    }

    override fun findMostRecent(name: String): CredentialVersion? {
        val credential = credentialDataService.find(name)

        if (credential == null) {
            return null
        } else {
            return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
                .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.uuid))
        }
    }

    override fun findByUuid(uuid: String): CredentialVersion? {
        val uuid = try {
            UUID.fromString(uuid)
        } catch (e: IllegalArgumentException) {
            throw EntryNotFoundException(ErrorMessages.RESOURCE_NOT_FOUND)
        }
        return credentialFactory
            .makeCredentialFromEntity(credentialVersionRepository.findOneByUuid(uuid))
    }

    override fun findAllCertificateCredentialsByCaName(caName: String): List<String> {
        val query = ("""select distinct credential.name from credential,
            credential_version, certificate_credential where credential.uuid=credential_version.credential_uuid
            and credential_version.uuid=certificate_credential.uuid and
            lower(certificate_credential.ca_name) like lower(?)""".trimMargin())
        val results = jdbcTemplate.queryForList<String>(query, String::class.java, caName)
        results.remove(caName)
        return results
    }

    override fun findContainingName(name: String): List<FindCredentialResult> {
        return findContainingName(name, "")
    }

    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        if ("" != expiresWithinDays) {
            return filterCertificates("%$name%", expiresWithinDays)
        }
        return findMatchingName("%$name%")
    }

    override fun findStartingWithPath(path: String): List<FindCredentialResult> {
        return findStartingWithPath(path, "")
    }

    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {

        var adjustedPath = StringUtils.prependIfMissing(path, "/")
        adjustedPath = StringUtils.appendIfMissing(adjustedPath, "/")

        if ("" != expiresWithinDays) {
            return filterCertificates(adjustedPath + "%", expiresWithinDays)
        }

        return findMatchingName(adjustedPath + "%")
    }

    override fun delete(name: String): Boolean {
        return credentialDataService.delete(name)
    }

    override fun findAllByName(name: String): List<CredentialVersion> {
        val credential = credentialDataService.find(name)

        return if (credential != null)
            credentialFactory.makeCredentialsFromEntities(
                credentialVersionRepository.findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.uuid))
        else
            Lists.newArrayList<CredentialVersion>()
    }

    override fun findNByName(name: String, numberOfVersions: Int): List<CredentialVersion> {
        val credential = credentialDataService.find(name)

        if (credential != null) {
            val credentialVersionData = credentialVersionRepository
                .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.uuid)
                .stream()
                .limit(numberOfVersions.toLong())
                .collect(Collectors.toList())
            return credentialFactory.makeCredentialsFromEntities(credentialVersionData)
        } else {
            return Lists.newArrayList<CredentialVersion>()
        }
    }

    override fun countByEncryptionKey(): Map<UUID, Long> {
        val map = HashMap<UUID, Long>()
        jdbcTemplate.query<Long>(
            (" SELECT count(*) as count, encryption_key_uuid FROM credential_version " +
                "LEFT JOIN encrypted_value ON credential_version.encrypted_value_uuid = encrypted_value.uuid " +
                "GROUP BY encrypted_value.encryption_key_uuid"),
            { rowSet, rowNum -> map.put(toUUID(rowSet.getObject("encryption_key_uuid")), rowSet.getLong("count")) }
        )
        return map
    }

    override fun findActiveByName(name: String): List<CredentialVersion>? {
        val credential = credentialDataService.find(name)
        val credentialVersionData: CredentialVersionData<*>
        val result = Lists.newArrayList<CredentialVersion>()
        if (credential != null) {
            credentialVersionData = credentialVersionRepository
                .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.uuid)

            if (credentialVersionData.getCredentialType() == CertificateCredentialVersionData.CREDENTIAL_TYPE) {
                return certificateVersionDataService.findActiveWithTransitional(name)
            }
            result.add(credentialFactory.makeCredentialFromEntity(credentialVersionData))

            return result
        } else {
            return Lists.newArrayList<CredentialVersion>()
        }
    }

    override fun count(): Long? {
        return credentialVersionRepository.count()
    }

    override fun countEncryptedWithKeyUuidIn(uuids: Collection<UUID>): Long? {
        return credentialVersionRepository.countByEncryptedCredentialValueEncryptionKeyUuidIn(uuids)
    }

    private fun toUUID(`object`: Any): UUID {
        if (`object`.javaClass == ByteArray::class.java) {
            val bytes = `object` as ByteArray
            if (bytes.size != 16) {
                throw IllegalArgumentException("Expected byte[] of length 16. Received length " + bytes.size)
            }
            var i = 0
            var msl: Long = 0
            while (i < 8) {
                msl = (msl shl 8) or ((bytes[i] and 0xFF.toByte()).toLong())
                i++
            }
            var lsl: Long = 0
            while (i < 16) {
                lsl = (lsl shl 8) or ((bytes[i] and 0xFF.toByte()).toLong())
                i++
            }
            return UUID(msl, lsl)
        } else if (`object`.javaClass == UUID::class.java) {
            return `object` as UUID
        } else {
            throw IllegalArgumentException("Expected byte[] or UUID type. Received " + `object`.javaClass.toString())
        }
    }

    private fun filterCertificates(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        val escapedPath = path.replace("_", "\\_")

        val expiresTimestamp = Timestamp.from(Instant.now().plus(Duration.ofDays(java.lang.Long.parseLong(expiresWithinDays))))

        val query = ("SELECT name.name,\n" +
            "       latest_credential_version.version_created_at,\n" +
            "       certificate_credential.expiry_date\n" +
            "FROM (\n" +
            "         SELECT credential_uuid, max(version_created_at) AS max_version_created_at\n" +
            "         FROM credential_version\n" +
            "         GROUP BY credential_uuid) AS credential_uuid_of_max_version_created_at\n" +
            "         INNER JOIN (SELECT * FROM credential WHERE lower(name) LIKE lower(?)) AS name\n" +
            "                    ON credential_uuid_of_max_version_created_at.credential_uuid = name.uuid\n" +
            "         INNER JOIN credential_version AS latest_credential_version\n" +
            "                    ON latest_credential_version.credential_uuid =\n" +
            "                       credential_uuid_of_max_version_created_at.credential_uuid\n" +
            "                        AND latest_credential_version.version_created_at =\n" +
            "                            credential_uuid_of_max_version_created_at.max_version_created_at\n" +
            "         INNER JOIN (SELECT * FROM certificate_credential) AS certificate_credential\n" +
            "                    ON latest_credential_version.uuid = certificate_credential.uuid\n" +
            "WHERE certificate_credential.expiry_date <= ?;")

        val certificateResults = jdbcTemplate.query<FindCredentialResult>(query,
            arrayOf<Any>(escapedPath, expiresTimestamp),
            { rowSet, rowNum ->
                val versionCreatedAt = Instant.ofEpochMilli(rowSet.getLong("version_created_at"))
                val name = rowSet.getString("name")
                val expiryDate = rowSet.getTimestamp("expiry_date").toInstant()
                FindCertificateResult(versionCreatedAt, name, expiryDate)
            }
        )
        return certificateResults
    }

    private fun findMatchingName(nameLike: String): List<FindCredentialResult> {
        val escapedNameLike = nameLike.replace("_", "\\_")

        val credentialResults = jdbcTemplate.query<FindCredentialResult>(
            (""" select name.name, credential_version.version_created_at from
                 (select max(version_created_at) as version_created_at, credential_uuid from
                    (select version_created_at, credential_uuid from credential_version LEFT OUTER JOIN
                        certificate_credential on credential_version.uuid = certificate_credential.uuid
                        WHERE transitional is false or transitional IS NULL) as credential_version
                    group by credential_uuid ) as credential_version
                 inner join
                    (select * from credential where lower(name) like lower(?) )
                    as name on credential_version.credential_uuid = name.uuid
                 order by version_created_at desc""".trimMargin()),
            arrayOf<Any>(escapedNameLike),
            { rowSet, rowNum ->
                val versionCreatedAt = Instant.ofEpochMilli(rowSet.getLong("version_created_at"))
                val name = rowSet.getString("name")
                FindCredentialResult(versionCreatedAt, name)
            }
        )
        return credentialResults
    }
}
