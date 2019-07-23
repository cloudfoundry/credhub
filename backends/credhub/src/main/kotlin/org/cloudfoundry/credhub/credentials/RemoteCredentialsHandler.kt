package org.cloudfoundry.credhub.credentials

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.protobuf.ByteString
import io.grpc.Status
import io.grpc.StatusRuntimeException
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.cloudfoundry.credhub.constants.CredentialWriteMode.CONVERGE
import org.cloudfoundry.credhub.constants.CredentialWriteMode.NO_OVERWRITE
import org.cloudfoundry.credhub.constants.CredentialWriteMode.OVERWRITE
import org.cloudfoundry.credhub.credential.CertificateCredentialValue
import org.cloudfoundry.credhub.credential.CredentialValue
import org.cloudfoundry.credhub.credential.JsonCredentialValue
import org.cloudfoundry.credhub.credential.RsaCredentialValue
import org.cloudfoundry.credhub.credential.SshCredentialValue
import org.cloudfoundry.credhub.credential.StringCredentialValue
import org.cloudfoundry.credhub.credential.UserCredentialValue
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator
import org.cloudfoundry.credhub.remote.RemoteBackendClient
import org.cloudfoundry.credhub.remote.grpc.FindResponse
import org.cloudfoundry.credhub.remote.grpc.FindResult
import org.cloudfoundry.credhub.remote.grpc.GetNVersionsResponse
import org.cloudfoundry.credhub.remote.grpc.GetResponse
import org.cloudfoundry.credhub.remote.grpc.SetResponse
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest
import org.cloudfoundry.credhub.requests.BaseCredentialSetRequest
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters
import org.cloudfoundry.credhub.requests.GenerationParameters
import org.cloudfoundry.credhub.requests.RsaGenerationParameters
import org.cloudfoundry.credhub.requests.SshGenerationParameters
import org.cloudfoundry.credhub.requests.StringGenerationParameters
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
    private val client: RemoteBackendClient,
    private val credentialGenerator: UniversalCredentialGenerator
) : CredentialsHandler {

    override fun getNCredentialVersions(credentialName: String, numberOfVersions: Int?): DataResponse {
        if (numberOfVersions == null) {
            return getAllCredentialVersions(credentialName)
        }
        val response: GetNVersionsResponse
        try {
            response = client.getNVersionsRequest(credentialName, userContextHolder.userContext.actor, numberOfVersions)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        val result = mutableListOf<CredentialView>()
        response.versionsList.forEach { v ->
            val credentialValue = getValueFromResponse(v.type, v.data)
            result.add(CredentialView(
                Instant.parse(v.versionCreatedAt),
                UUID.fromString(v.id),
                credentialName,
                v.type,
                credentialValue
            ))
        }

        return DataResponse(result)
    }

    override fun getAllCredentialVersions(credentialName: String): DataResponse {
        val response: GetNVersionsResponse
        try {
            response = client.getAllVersionsRequest(credentialName, userContextHolder.userContext.actor)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        val result = mutableListOf<CredentialView>()
        response.versionsList.forEach { v ->
            val credentialValue = getValueFromResponse(v.type, v.data)
            result.add(CredentialView(
                Instant.parse(v.versionCreatedAt),
                UUID.fromString(v.id),
                credentialName,
                v.type,
                credentialValue
            ))
        }

        return DataResponse(result)
    }

    override fun getCurrentCredentialVersions(credentialName: String): DataResponse {
        val actor = userContextHolder.userContext.actor
        val response: GetResponse
        try {
            response = client.getByNameRequest(credentialName, actor)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

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
        val response: GetResponse
        try {
            response = client.getByIdRequest(credentialUUID, actor)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        val credentialValue = getValueFromResponse(response.type, response.data)

        return CredentialView(
            Instant.parse(response.versionCreatedAt),
            UUID.fromString(response.id),
            response.name,
            response.type,
            credentialValue
        )
    }

    override fun findContainingName(name: String, expiresWithinDays: String): List<FindCredentialResult> {
        val actor = userContextHolder.userContext.actor
        val response: FindResponse
        try {
            response = client.findContainingNameRequest(name, actor)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }

        return getListFromResponse(response.resultsList)
    }

    override fun findStartingWithPath(path: String, expiresWithinDays: String): List<FindCredentialResult> {
        val actor = userContextHolder.userContext.actor
        val response: FindResponse
        try {
            response = client.findStartingWithPathRequest(path, actor)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }
        return getListFromResponse(response.resultsList)
    }

    override fun generateCredential(generateRequest: BaseCredentialGenerateRequest): CredentialView {
        val getResponse = getCredentialFromRequest(generateRequest)
        val credentialValue: CredentialValue
        val name = generateRequest.name
        val actor = userContextHolder.userContext.actor
        val type = generateRequest.type
        val versionCreatedAt: Instant
        val uuid: UUID

        if (getResponse != null) {
            credentialValue = getValueFromResponse(getResponse.type, getResponse.data)
            versionCreatedAt = Instant.parse(getResponse.versionCreatedAt)
            uuid = UUID.fromString(getResponse.id)
        } else {
            val value = credentialGenerator.generate(generateRequest)
            val data = createByteStringFromData(type, value)
            val genParams = createByteStringFromGenerationParameters(type, generateRequest.generationParameters)
            val response: SetResponse
            try {
                response = client.setRequest(name, type, data, actor, genParams)
            } catch (e: StatusRuntimeException) {
                throw handleException(e)
            }
            credentialValue = getValueFromResponse(response.type, response.data)
            versionCreatedAt = Instant.parse(response.versionCreatedAt)
            uuid = UUID.fromString(response.id)
        }

        return CredentialView(
            versionCreatedAt,
            uuid,
            name,
            type,
            credentialValue
        )
    }

    override fun setCredential(setRequest: BaseCredentialSetRequest<*>): CredentialView {
        val name = setRequest.name
        val type = setRequest.type
        val data = createByteStringFromData(type, setRequest.credentialValue)
        val actor = userContextHolder.userContext.actor
        val response: SetResponse
        try {
            response = client.setRequest(name, type, data, actor, ByteString.EMPTY)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }
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
        val actor = userContextHolder.userContext.actor

        try {
            client.deleteRequest(credentialName, actor)
        } catch (e: StatusRuntimeException) {
            throw handleException(e)
        }
    }

    private fun getListFromResponse(results: List<FindResult>): List<FindCredentialResult> {
        return results.map { result ->
            FindCredentialResult(Instant.parse(result.versionCreatedAt), result.name)
        }
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
                    jsonNode["certificate_authority"]?.booleanValue() ?: false,
                    jsonNode["self_signed"]?.booleanValue() ?: false,
                    jsonNode["generated"]?.booleanValue() ?: false,
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
                    "transitional" to certificateCredentialValue.isTransitional,
                    "certificate_authority" to certificateCredentialValue.isCertificateAuthority,
                    "self_signed" to certificateCredentialValue.isSelfSigned,
                    "generated" to certificateCredentialValue.generated

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

    internal fun createByteStringFromGenerationParameters(type: String, generationParams: GenerationParameters): ByteString {
        return when (type) {
            "password" -> {
                val stringGenerationParameters = generationParams as StringGenerationParameters
                val json = objectMapper.writeValueAsString(mapOf(
                    "include_special" to stringGenerationParameters.isIncludeSpecial,
                    "exclude_number" to stringGenerationParameters.isExcludeNumber,
                    "exclude_upper" to stringGenerationParameters.isExcludeUpper,
                    "exclude_lower" to stringGenerationParameters.isExcludeLower,
                    "username" to stringGenerationParameters.username,
                    "length" to stringGenerationParameters.length
                ))

                ByteString.copyFromUtf8(json)
            }

            "ssh" -> {
                val sshGenerationParameters = generationParams as SshGenerationParameters
                val json = objectMapper.writeValueAsString(mapOf(
                    "key_length" to sshGenerationParameters.keyLength,
                    "ssh_comment" to sshGenerationParameters.sshComment
                ))

                ByteString.copyFromUtf8(json)
            }

            "rsa" -> {
                val rsaGenerationParameters = generationParams as RsaGenerationParameters
                val json = objectMapper.writeValueAsString(mapOf(
                    "key_length" to rsaGenerationParameters.keyLength
                ))

                ByteString.copyFromUtf8(json)
            }

            "user" -> {
                val userGenerationParameters = generationParams as StringGenerationParameters
                val json = objectMapper.writeValueAsString(mapOf(
                    "include_special" to userGenerationParameters.isIncludeSpecial,
                    "exclude_number" to userGenerationParameters.isExcludeNumber,
                    "exclude_upper" to userGenerationParameters.isExcludeUpper,
                    "exclude_lower" to userGenerationParameters.isExcludeLower,
                    "username" to userGenerationParameters.username,
                    "length" to userGenerationParameters.length

                ))

                ByteString.copyFromUtf8(json)
            }

            "certificate" -> {
                val certGenerationParams = generationParams as CertificateGenerationParameters
                val names = certGenerationParams.x500Principal.getName("RFC1779")
                val x500Names: MutableMap<String, String> = mutableMapOf()
                val namesArray = names.split(",")
                namesArray.forEach {
                    val kv = it.split('=')
                    x500Names[kv[0]] = kv[1]
                }

                val json = objectMapper.writeValueAsString(mapOf(

                    "is_ca" to certGenerationParams.isCa,
                    "organization_unit" to x500Names["OU"],
                    "organization" to x500Names["O"],
                    "state" to x500Names["ST"],
                    "country" to x500Names["C"],
                    "locality" to x500Names["L"],
                    "common_name" to x500Names["CN"],
                    "key_length" to certGenerationParams.keyLength,
                    "duration" to certGenerationParams.duration,
                    "self_signed" to certGenerationParams.isSelfSigned,
                    "ca_name" to certGenerationParams.caName,
                    "alternative_names" to certGenerationParams.alternativeNames,
                    "key_usage" to certGenerationParams.keyUsage,
                    "extended_key_usage" to certGenerationParams.extendedKeyUsage
                ).filterValues { it != null })
                ByteString.copyFromUtf8(json)
            }

            else -> throw Exception()
        }
    }

    private fun getGenerationParametersFromResponse(type: String, generationParams: ByteString): GenerationParameters {
        return when (type) {
            "password" -> {
                val jsonString = generationParams.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString) ?: return StringGenerationParameters()

                val generationParameters = StringGenerationParameters()

                if (jsonNode.hasNonNull("length")) {
                    generationParameters.length = jsonNode["length"].intValue()
                }
                if (jsonNode.hasNonNull("username")) {
                    generationParameters.username = jsonNode["username"].textValue()
                }
                if (jsonNode.hasNonNull("exclude_lower")) {
                    generationParameters.isExcludeLower = jsonNode["exclude_lower"].booleanValue()
                }
                if (jsonNode.hasNonNull("exlude_upper")) {
                    generationParameters.isExcludeUpper = jsonNode["exlude_upper"].booleanValue()
                }
                if (jsonNode.hasNonNull("exclude_number")) {
                    generationParameters.isExcludeNumber = jsonNode["exclude_number"].booleanValue()
                }
                if (jsonNode.hasNonNull("include_special")) {
                    generationParameters.isIncludeSpecial = jsonNode["include_special"].booleanValue()
                }

                generationParameters
            }

            "user" -> {
                val jsonString = generationParams.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString) ?: return StringGenerationParameters()

                val generationParameters = StringGenerationParameters()

                if (jsonNode.hasNonNull("length")) {
                    generationParameters.length = jsonNode["length"].intValue()
                }
                if (jsonNode.hasNonNull("username")) {
                    generationParameters.username = jsonNode["username"].textValue()
                }
                if (jsonNode.hasNonNull("exclude_lower")) {
                    generationParameters.isExcludeLower = jsonNode["exclude_lower"].booleanValue()
                }
                if (jsonNode.hasNonNull("exlude_upper")) {
                    generationParameters.isExcludeUpper = jsonNode["exlude_upper"].booleanValue()
                }
                if (jsonNode.hasNonNull("exclude_number")) {
                    generationParameters.isExcludeNumber = jsonNode["exclude_number"].booleanValue()
                }
                if (jsonNode.hasNonNull("include_special")) {
                    generationParameters.isIncludeSpecial = jsonNode["include_special"].booleanValue()
                }
                generationParameters
            }

            "ssh" -> {
                val jsonString = generationParams.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString) ?: return SshGenerationParameters()

                val generationParameters = SshGenerationParameters()

                if (jsonNode.hasNonNull("key_length")) {
                    generationParameters.keyLength = jsonNode["key_length"].intValue()
                }
                if (jsonNode.hasNonNull("ssh_comment")) {
                    generationParameters.sshComment = jsonNode["ssh_comment"].textValue()
                }

                generationParameters
            }

            "rsa" -> {
                val jsonString = generationParams.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString) ?: return RsaGenerationParameters()

                val generationParameters = RsaGenerationParameters()

                if (jsonNode.hasNonNull("key_length")) {
                    generationParameters.keyLength = jsonNode["key_length"].intValue()
                }

                generationParameters
            }

            "certificate" -> {
                val jsonString = generationParams.toStringUtf8()
                val jsonNode = objectMapper.readTree(jsonString)
                    ?: return CertificateGenerationParameters(CertificateGenerationRequestParameters())

                val generationRequestParameters = CertificateGenerationRequestParameters()

                if (jsonNode.hasNonNull("organization")) {
                    generationRequestParameters.organization = jsonNode["organization"].textValue()
                }
                if (jsonNode.hasNonNull("state")) {
                    generationRequestParameters.state = jsonNode["state"].textValue()
                }
                if (jsonNode.hasNonNull("country")) {
                    generationRequestParameters.country = jsonNode["country"].textValue()
                }
                if (jsonNode.hasNonNull("common_name")) {
                    generationRequestParameters.commonName = jsonNode["common_name"].textValue()
                }
                if (jsonNode.hasNonNull("organization_unit")) {
                    generationRequestParameters.organizationUnit = jsonNode["organization_unit"].textValue()
                }
                if (jsonNode.hasNonNull("locality")) {
                    generationRequestParameters.locality = jsonNode["locality"].textValue()
                }
                if (jsonNode.hasNonNull("is_ca")) {
                    generationRequestParameters.setIsCa(jsonNode["is_ca"].booleanValue())
                }
                if (jsonNode.hasNonNull("key_usage")) {
                    generationRequestParameters.keyUsage = arrayOf(jsonNode["key_usage"].textValue())
                }
                if (jsonNode.hasNonNull("extended_key_usage")) {
                    generationRequestParameters.extendedKeyUsage = arrayOf(jsonNode["extended_key_usage"].textValue())
                }
                if (jsonNode.hasNonNull("alternative_names")) {
                    var altNames: MutableList<String> = ArrayList()
                    jsonNode["alternative_names"]["names"].forEach {
                        altNames.add(it["name"]["string"].toString())
                    }
                    generationRequestParameters.alternativeNames = altNames.toTypedArray()
                }
                if (jsonNode.hasNonNull("ca_name")) {
                    generationRequestParameters.caName = jsonNode["ca_name"].textValue()
                }
                if (jsonNode.hasNonNull("self_signed")) {
                    generationRequestParameters.isSelfSigned = jsonNode["self_signed"].booleanValue()
                }
                if (jsonNode.hasNonNull("duration")) {
                    generationRequestParameters.duration = jsonNode["duration"].intValue()
                }
                if (jsonNode.hasNonNull("key_length")) {
                    generationRequestParameters.keyLength = jsonNode["key_length"].intValue()
                }

                CertificateGenerationParameters(generationRequestParameters)
            }

            else -> throw Exception()
        }
    }

    private fun getCredentialFromRequest(credentialRequest: BaseCredentialGenerateRequest): GetResponse? {
        val originalValue: GetResponse
        try {
            originalValue = client.getByNameRequest(credentialRequest.name, userContextHolder.userContext.actor)
            val originalGenerationParameters =
                getGenerationParametersFromResponse(originalValue.type, originalValue.generationParameters)

            if (credentialRequest.mode == OVERWRITE || credentialRequest.isOverwrite) {
                return null
            }

            if (credentialRequest.mode == CONVERGE || credentialRequest.mode == null) {
                return if (originalGenerationParameters != credentialRequest.generationParameters) {
                    null
                } else {
                    originalValue
                }
            }

            if (credentialRequest.mode == NO_OVERWRITE) {
                return originalValue
            }
        } catch (e: StatusRuntimeException) {
            return null
        }
        return originalValue
    }

    private fun handleException(e: StatusRuntimeException): Exception {
        if (e.status.code == Status.NOT_FOUND.code) {
            return EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS)
        }
        return RuntimeException("Request failed with status code: ${e.status.code}")
    }
}
