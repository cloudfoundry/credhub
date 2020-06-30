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
import java.util.HashMap
import java.util.function.Supplier

@Component
class GenerationRequestGenerator {
    private val regeneratableTypeProducers: MutableMap<String, Supplier<Regeneratable>>
    fun createGenerateRequest(credentialVersion: CredentialVersion?): BaseCredentialGenerateRequest {
        if (credentialVersion == null) {
            throw EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        val regeneratable = regeneratableTypeProducers
            .getOrDefault(credentialVersion.getCredentialType(), Supplier<Regeneratable> { NotRegeneratable() })
            .get()
        return regeneratable.createGenerateRequest(credentialVersion)
    }

    init {
        regeneratableTypeProducers = HashMap()
        regeneratableTypeProducers["password"] = Supplier<Regeneratable> { PasswordCredentialRegeneratable() }
        regeneratableTypeProducers["user"] = Supplier<Regeneratable> { UserCredentialRegeneratable() }
        regeneratableTypeProducers["ssh"] = Supplier<Regeneratable> { SshCredentialRegeneratable() }
        regeneratableTypeProducers["rsa"] = Supplier<Regeneratable> { RsaCredentialRegeneratable() }
        regeneratableTypeProducers["certificate"] = Supplier<Regeneratable> { CertificateCredentialRegeneratable() }
    }
}
