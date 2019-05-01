package org.cloudfoundry.credhub.data

import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException
import org.cloudfoundry.credhub.exceptions.MissingCertificateException
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository
import org.cloudfoundry.credhub.utils.CertificateReader
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
class ExpiryDateMigration @Autowired
constructor(private val credentialVersionRepository: CredentialVersionRepository) {
    fun migrate() {
        var numberOfInvalidCertsFound = 0
        while (credentialVersionRepository.countVersionsWithNullExpirationDate() != numberOfInvalidCertsFound) {
            val data = credentialVersionRepository.findUpTo1000VersionsWithNullExpirationDate(numberOfInvalidCertsFound)
            for (version in data) {
                if (version is CertificateCredentialVersionData) {
                    val certificate = version.certificate
                    try {
                        val reader = CertificateReader(certificate)
                        version.expiryDate = reader.notAfter
                    } catch (e: RuntimeException) {
                        printErrorMessage(e, version)
                        numberOfInvalidCertsFound++
                    }
                }
            }
            credentialVersionRepository.saveAll(data)
        }
    }

    fun printErrorMessage(e: RuntimeException, version: CertificateCredentialVersionData) {
        var message = String.format("Unexpected exception reading certificate with name %s: %s", version.name, e.toString())
        when (e) {
            is MalformedCertificateException ->
                message = String.format("can't read certificate with name %s", version.getName())
            is MissingCertificateException ->
                message = String.format("missing certificate with name %s", version.name)
        }
        LOGGER.warn(message)
    }

    companion object {
        private val LOGGER = LogManager.getLogger(ExpiryDateMigration::class.java)
    }
}
