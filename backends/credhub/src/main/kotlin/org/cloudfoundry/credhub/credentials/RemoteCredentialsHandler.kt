package org.cloudfoundry.credhub.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.protobuf.ByteString
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.remote.RemoteBackendClient
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
        val name = setRequest.name
        val type = setRequest.type
        val data = createByteStringFromData(type, setRequest.credentialValue)
        val actor = userContextHolder.userContext.actor

        val response = client.setRequest(name, type, data, actor)
        val credentialValue = getValueFromResponse(response.type, response.data)

        return CredentialView(
            Instant.parse(response.versionCreatedAt),
            UUID.fromString(response.id),
            response.name,
            response.type,
            credentialValue
        )
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

        val credentialValue = getValueFromResponse(response.type, response.data)

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

        val credentialValue = getValueFromResponse(response.type, response.data)

        return CredentialView(
            Instant.parse(response.versionCreatedAt),
            UUID.fromString(response.id),
            response.name,
            response.type,
            credentialValue
        )
    }

    private fun getValueFromResponse(type: String, data: ByteString): CredentialValue {
        return when (type) {
            "value" -> StringCredentialValue(data.toStringUtf8())
            "password" -> StringCredentialValue(data.toStringUtf8())
            "certificate" -> {
                val jsonString = data.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString)

                CertificateCredentialValue(
                    jsonNode["ca"]?.textValue(),
                    jsonNode["certificate"]?.textValue(),
                    jsonNode["private_key"]?.textValue(),
                    jsonNode["ca_name"]?.textValue(),
                    jsonNode["transitional"]?.booleanValue() ?: false
                )
            }
            "json" -> {
                val jsonString = data.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString)
                JsonCredentialValue(jsonNode)
            }
            "user" -> {
                val jsonString = data.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString)
                UserCredentialValue(
                    jsonNode["username"]?.textValue(),
                    jsonNode["password"]?.textValue(),
                    jsonNode["salt"]?.textValue()
                )
            }
            "rsa" -> {
                val jsonString = data.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString)
                RsaCredentialValue(
                    jsonNode["public_key"]?.textValue(),
                    jsonNode["private_key"]?.textValue()
                )
            }
            "ssh" -> {
                val jsonString = data.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString)
                SshCredentialValue(
                    jsonNode["public_key"]?.textValue(),
                    jsonNode["private_key"]?.textValue(),
                    jsonNode["public_key_fingerprint"]?.textValue()

                )
            }
            else -> throw Exception()
        }
    }

    internal fun createByteStringFromData(type: String, data: CredentialValue): ByteString {
        return when (type) {
            "value" -> {
                val stringCredentialValue = data as StringCredentialValue
                val value = stringCredentialValue.stringCredential
                ByteString.copyFromUtf8(value)
            }

            "password" -> {
                val stringCredentialValue = data as StringCredentialValue
                val value = stringCredentialValue.stringCredential
                ByteString.copyFromUtf8(value)
            }

            "certificate" -> {
                val certificateCredentialValue = data as CertificateCredentialValue

                val json = objectMapper.writeValueAsString(mapOf(
                    "ca" to certificateCredentialValue.ca,
                    "ca_name" to certificateCredentialValue.caName,
                    "certificate" to certificateCredentialValue.certificate,
                    "private_key" to certificateCredentialValue.privateKey,
                    "transitional" to certificateCredentialValue.isTransitional
                ))
                ByteString.copyFromUtf8(json)
            }
            "json" -> {
                val jsonCredentialValue = data as JsonCredentialValue
                val value: JsonNode = jsonCredentialValue.value
                val valueString = value.toString()
                ByteString.copyFromUtf8(valueString)
            }
            "user" -> {
                val userCredentialValue = data as UserCredentialValue

                val json = objectMapper.writeValueAsString(mapOf(
                    "username" to userCredentialValue.username,
                    "password" to userCredentialValue.password,
                    "salt" to userCredentialValue.salt
                ))
                ByteString.copyFromUtf8(json)
            }
            "rsa" -> {
                val rsaCredentialValue = data as RsaCredentialValue

                val json = objectMapper.writeValueAsString(mapOf(
                    "public_key" to rsaCredentialValue.publicKey,
                    "private_key" to rsaCredentialValue.privateKey
                ))
                ByteString.copyFromUtf8(json)
            }
            "ssh" -> {
                val sshCredentialValue = data as SshCredentialValue

                val json = objectMapper.writeValueAsString(mapOf(
                    "public_key" to sshCredentialValue.publicKey,
                    "private_key" to sshCredentialValue.privateKey,
                    "public_key_fingerprint" to sshCredentialValue.publicKeyFingerprint
                ))
                ByteString.copyFromUtf8(json)
            }
            else -> throw Exception()
        }
    }
}
