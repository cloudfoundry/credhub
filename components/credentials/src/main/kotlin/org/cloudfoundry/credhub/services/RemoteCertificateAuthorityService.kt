package org.cloudfoundry.credhub.services

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.protobuf.ByteString
import io.grpc.Status
import io.grpc.StatusRuntimeException
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.GetResponse
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Component

@Component
@Profile("remote")
class RemoteCertificateAuthorityService(
    private val userContextHolder: UserContextHolder,
    private val objectMapper: ObjectMapper,
    private val client: RemoteBackendClient,
) : CertificateAuthorityService {

    override fun findActiveVersion(caName: String): CertificateCredentialValue? {
        val response: GetResponse
        try {
            response = client.getByNameRequest(caName, userContextHolder.userContext?.actor.toString())
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        return toCredentialValue(response.data)
    }

    override fun findTransitionalVersion(caName: String): CertificateCredentialValue? {
        // To be changed when certificates endpoint is implemented
        return null
    }

    private fun handleException(e: StatusRuntimeException): Exception {
        if (e.status.code == Status.NOT_FOUND.code) {
            return EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        return RuntimeException("Request failed with status code: ${e.status.code}")
    }

    private fun toCredentialValue(data: ByteString): CertificateCredentialValue {
        val jsonString = data.toStringUtf8()
        val jsonNode = objectMapper.readTree(jsonString)
        return CertificateCredentialValue(
            jsonNode["ca"]?.textValue(),
            jsonNode["certificate"]?.textValue(),
            jsonNode["private_key"]?.textValue(),
            jsonNode["ca_name"]?.textValue(),
            jsonNode["certificate_authority"]?.booleanValue() ?: false,
            jsonNode["self_signed"]?.booleanValue() ?: false,
            jsonNode["generated"]?.booleanValue() ?: false,
            jsonNode["transitional"]?.booleanValue() ?: false,
        )
    }
}
