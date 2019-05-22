package org.cloudfoundry.credhub.credentials

import com.fasterxml.jackson.databind.ObjectMapper
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.GetResponse
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.views.CredentialView
import org.cloudfoundry.credhub.views.DataResponse
import org.cloudfoundry.credhub.views.FindCredentialResult
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.UUID

@Service
@Profile("remote")
class RemoteCredentialsHandler(
    private val userContextHolder: UserContextHolder,
    private val objectMapper: ObjectMapper,
    private val client: RemoteBackendClient
) : CredentialsHandler {

    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun generateCredential(generateRequest: BaseCredentialGenerateRequest): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun setCredential(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun deleteCredential(credentialName: String) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getAllCredentialVersions(credentialName: String): DataResponse {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun getCurrentCredentialVersions(credentialName: String): DataResponse {

        val actor = userContextHolder.userContext.actor
        val response = client.getByNameRequest(credentialName, actor)

        val credentialValue = getValueFromResponse(response)

        return DataResponse(listOf(CredentialView(
            Instant.parse(response.versionCreatedAt),
            UUID.fromString(response.id),
            credentialName,
            response.type,
            credentialValue
        )))
    }

    override fun getCredentialVersionByUUID(credentialUUID: String): CredentialView {
        val actor = userContextHolder.userContext.actor
        val response = client.getByIdRequest(credentialUUID, actor)

        val credentialValue = getValueFromResponse(response)

        return CredentialView(
            Instant.parse(response.versionCreatedAt),
            UUID.fromString(response.id),
            response.name,
            response.type,
            credentialValue
        )
    }

    private fun getValueFromResponse(response: GetResponse): CredentialValue? {
        val credentialValue: CredentialValue
        when (response.type) {
            "value" -> credentialValue = StringCredentialValue(response.data.toStringUtf8())
            "password" -> credentialValue = StringCredentialValue(response.data.toStringUtf8())
            "certificate" -> credentialValue = objectMapper.readValue(response.data.toStringUtf8(), CertificateCredentialValue::class.java)
            "json" -> credentialValue = objectMapper.readValue(response.data.toStringUtf8(), JsonCredentialValue::class.java)
            "user" -> credentialValue = objectMapper.readValue(response.data.toStringUtf8(), UserCredentialValue::class.java)
            "rsa" -> credentialValue = objectMapper.readValue(response.data.toStringUtf8(), RsaCredentialValue::class.java)
            "ssh" -> credentialValue = objectMapper.readValue(response.data.toStringUtf8(), SshCredentialValue::class.java)
            else -> throw Exception()
        }
        return credentialValue
    }
}
