package org.cloudfoundry.credhub.generate

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.domain.CredentialVersion
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.service.regeneratables.CertificateCredentialRegeneratable
import org.cloudfoundry.credhub.service.regeneratables.NotRegeneratable
import org.cloudfoundry.credhub.service.regeneratables.PasswordCredentialRegeneratable
import org.cloudfoundry.credhub.service.regeneratables.Regeneratable
import org.cloudfoundry.credhub.service.regeneratables.RsaCredentialRegeneratable
import org.cloudfoundry.credhub.service.regeneratables.SshCredentialRegeneratable
import org.cloudfoundry.credhub.service.regeneratables.UserCredentialRegeneratable
import org.springframework.stereotype.Component

@Component
class GenerationRequestGenerator(
    private val certificateCredentialRegeneratable: CertificateCredentialRegeneratable,
) {
    private val regeneratableTypeProducers: MutableMap<String, () -> Regeneratable>

    init {
        regeneratableTypeProducers = HashMap()
        regeneratableTypeProducers["password"] = { PasswordCredentialRegeneratable() }
        regeneratableTypeProducers["user"] = { UserCredentialRegeneratable() }
        regeneratableTypeProducers["ssh"] = { SshCredentialRegeneratable() }
        regeneratableTypeProducers["rsa"] = { RsaCredentialRegeneratable() }
        regeneratableTypeProducers["certificate"] = { certificateCredentialRegeneratable } // Use injected instance
    }

    fun createGenerateRequest(credentialVersion: CredentialVersion?): BaseCredentialGenerateRequest {
        if (credentialVersion == null) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        val regeneratable =
            regeneratableTypeProducers
                .getOrDefault(credentialVersion.getCredentialType()) { NotRegeneratable() }
                .invoke()
        return regeneratable.createGenerateRequest(credentialVersion)
    }
}
