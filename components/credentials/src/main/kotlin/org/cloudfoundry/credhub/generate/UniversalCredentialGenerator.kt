package org.cloudfoundry.credhub.generate

import java.util.HashMap
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.generators.CertificateGenerator
import org.cloudfoundry.credhub.generators.CredentialGenerator
import org.cloudfoundry.credhub.generators.PasswordCredentialGenerator
import org.cloudfoundry.credhub.generators.RsaGenerator
import org.cloudfoundry.credhub.generators.SshGenerator
import org.cloudfoundry.credhub.generators.UserGenerator
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
class UniversalCredentialGenerator @Autowired constructor(
    passwordCredentialGenerator: PasswordCredentialGenerator,
    userGenerator: UserGenerator,
    sshGenerator: SshGenerator,
    rsaGenerator: RsaGenerator,
    certificateGenerator: CertificateGenerator
) {
    private val credentialGenerators: MutableMap<String, CredentialGenerator<*>>
    fun generate(generateRequest: BaseCredentialGenerateRequest): CredentialValue {
        val generator = credentialGenerators[generateRequest.type]
        return generator!!.generateCredential(generateRequest.generationParameters)
    }

    init {
        credentialGenerators = HashMap()
        credentialGenerators["password"] = passwordCredentialGenerator
        credentialGenerators["user"] = userGenerator
        credentialGenerators["ssh"] = sshGenerator
        credentialGenerators["rsa"] = rsaGenerator
        credentialGenerators["certificate"] = certificateGenerator
    }
}
