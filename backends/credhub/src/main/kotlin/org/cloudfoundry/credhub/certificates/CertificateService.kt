package org.cloudfoundry.credhub.certificates

import org.cloudfoundry.credhub.PermissionOperation.READ
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.data.CertificateVersionDataService
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.services.PermissionCheckingService
import org.springframework.stereotype.Service

@Service
class CertificateService(val certificateVersionDataService: CertificateVersionDataService,
                         val permissionCheckingService: PermissionCheckingService,
                         val userContextHolder: UserContextHolder) {



    fun findByCredentialUuid(uuid: String): CertificateCredentialVersion {
        val certificate = certificateVersionDataService.findByCredentialUUID(uuid)
            as? CertificateCredentialVersion ?: throw EntryNotFoundException("error.credential.invalid_access")

        val hasPermission = permissionCheckingService.hasPermission(
            userContextHolder.userContext.actor,
            certificate.name,
            READ
        )

        if (!hasPermission) {
            throw EntryNotFoundException("error.credential.invalid_access")
        }

        return certificate

    }
}
