package org.cloudfoundry.credhub.domain

import org.cloudfoundry.credhub.constants.CredentialType
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData
import org.cloudfoundry.credhub.entity.SshCredentialVersionData
import org.cloudfoundry.credhub.entity.UserCredentialVersionData
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData
import org.cloudfoundry.credhub.requests.GenerationParameters
import org.cloudfoundry.credhub.requests.StringGenerationParameters
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component

@Component
class CredentialFactory @Autowired internal constructor(private val encryptor: Encryptor) {
    fun makeCredentialFromEntity(credentialVersionData: CredentialVersionData<*>?): CredentialVersion? {
        if (credentialVersionData == null) {
            return null
        }
        val returnValue: CredentialVersion
        returnValue = if (credentialVersionData is CertificateCredentialVersionData) {
            CertificateCredentialVersion((credentialVersionData as CertificateCredentialVersionData?)!!)
        } else if (credentialVersionData is PasswordCredentialVersionData) {
            PasswordCredentialVersion(credentialVersionData as PasswordCredentialVersionData?)
        } else if (credentialVersionData is RsaCredentialVersionData) {
            RsaCredentialVersion(credentialVersionData as RsaCredentialVersionData?)
        } else if (credentialVersionData is SshCredentialVersionData) {
            SshCredentialVersion(credentialVersionData as SshCredentialVersionData?)
        } else if (credentialVersionData is ValueCredentialVersionData) {
            ValueCredentialVersion(credentialVersionData as ValueCredentialVersionData?)
        } else if (credentialVersionData is JsonCredentialVersionData) {
            JsonCredentialVersion(credentialVersionData as JsonCredentialVersionData?)
        } else if (credentialVersionData is UserCredentialVersionData) {
            UserCredentialVersion(credentialVersionData as UserCredentialVersionData?)
        } else {
            throw RuntimeException("Unrecognized type: " + credentialVersionData.javaClass.name)
        }
        returnValue.setEncryptor(encryptor)
        return returnValue
    }

    fun makeCredentialsFromEntities(daos: List<CredentialVersionData<*>?>): List<CredentialVersion> {
        return daos.mapNotNull { credentialVersionData: CredentialVersionData<*>? ->
            makeCredentialFromEntity(credentialVersionData) }.toList()
    }

    fun makeNewCredentialVersion(
        type: CredentialType?,
        name: String?,
        credentialValue: CredentialValue?,
        existingCredentialVersion: CredentialVersion?,
        passwordGenerationParameters: GenerationParameters?
    ): CredentialVersion {
        val credentialVersion = when (type) {
            CredentialType.PASSWORD -> PasswordCredentialVersion(
                credentialValue as StringCredentialValue?,
                passwordGenerationParameters as StringGenerationParameters?,
                encryptor
            )
            CredentialType.CERTIFICATE -> CertificateCredentialVersion((credentialValue as CertificateCredentialValue?)!!, encryptor)
            CredentialType.VALUE -> ValueCredentialVersion(credentialValue as StringCredentialValue?, encryptor)
            CredentialType.RSA -> RsaCredentialVersion(credentialValue as RsaCredentialValue?, encryptor)
            CredentialType.SSH -> SshCredentialVersion(credentialValue as SshCredentialValue?, encryptor)
            CredentialType.JSON -> JsonCredentialVersion(credentialValue as JsonCredentialValue?, encryptor)
            CredentialType.USER -> UserCredentialVersion(
                credentialValue as UserCredentialValue?,
                passwordGenerationParameters as StringGenerationParameters?,
                encryptor
            )
            else -> throw RuntimeException("Unrecognized type: $type")
        }
        if (existingCredentialVersion == null) {
            credentialVersion.createName(name!!)
        } else {
            credentialVersion.copyNameReferenceFrom(existingCredentialVersion)
        }
        return credentialVersion
    }
}
