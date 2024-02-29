package org.cloudfoundry.credhub.domain

import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.entities.Credential
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
class CertificateCredentialFactory @Autowired
internal constructor(private val encryptor: Encryptor) {

    fun makeNewCredentialVersion(
        certificateCredential: Credential,
        credentialValue: CertificateCredentialValue
    ): CertificateCredentialVersion {
        val version = CertificateCredentialVersion(credentialValue, certificateCredential.name!!, encryptor)
        version.credential = certificateCredential

        return version
    }
}
