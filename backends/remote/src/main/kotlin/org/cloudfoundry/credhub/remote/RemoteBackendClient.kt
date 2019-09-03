package org.cloudfoundry.credhub.remote

import com.google.protobuf.ByteString
import io.grpc.internal.GrpcUtil.DEFAULT_KEEPALIVE_TIMEOUT_NANOS
import io.grpc.netty.GrpcSslContexts
import io.grpc.netty.NegotiationType
import io.grpc.netty.NettyChannelBuilder
import io.netty.channel.Channel
import io.netty.channel.EventLoopGroup
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDomainSocketChannel
import io.netty.channel.epoll.EpollEventLoopGroup
import io.netty.channel.kqueue.KQueue
import io.netty.channel.kqueue.KQueueDomainSocketChannel
import io.netty.channel.kqueue.KQueueEventLoopGroup
import io.netty.channel.unix.DomainSocketAddress
import io.netty.handler.ssl.SslContext
import org.apache.commons.lang3.StringUtils
import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.remote.grpc.CredentialServiceGrpc
import org.cloudfoundry.credhub.remote.grpc.DeleteByNameRequest
import org.cloudfoundry.credhub.remote.grpc.DeletePermissionRequest
import org.cloudfoundry.credhub.remote.grpc.FindContainingNameRequest
import org.cloudfoundry.credhub.remote.grpc.FindPermissionByPathAndActorRequest
import org.cloudfoundry.credhub.remote.grpc.FindResponse
import org.cloudfoundry.credhub.remote.grpc.FindStartingWithPathRequest
import org.cloudfoundry.credhub.remote.grpc.GetAllVersionsRequest
import org.cloudfoundry.credhub.remote.grpc.GetByIdRequest
import org.cloudfoundry.credhub.remote.grpc.GetByNameRequest
import org.cloudfoundry.credhub.remote.grpc.GetNVersionsRequest
import org.cloudfoundry.credhub.remote.grpc.GetNVersionsResponse
import org.cloudfoundry.credhub.remote.grpc.GetPermissionRequest
import org.cloudfoundry.credhub.remote.grpc.GetResponse
import org.cloudfoundry.credhub.remote.grpc.PatchPermissionsRequest
import org.cloudfoundry.credhub.remote.grpc.PermissionsResponse
import org.cloudfoundry.credhub.remote.grpc.PutPermissionsRequest
import org.cloudfoundry.credhub.remote.grpc.SetRequest
import org.cloudfoundry.credhub.remote.grpc.SetResponse
import org.cloudfoundry.credhub.remote.grpc.WritePermissionsRequest
import org.cloudfoundry.credhub.utils.StringUtil
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import java.io.ByteArrayInputStream
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException

@Service
@Profile("remote")
class RemoteBackendClient(
    @Value("\${backend.socket_file}") private val socketFile: String,
    @Value("\${backend.host}") private val host: String,
    @Value("\${backend.ca_cert}") private val caCert: String
) {

    companion object {
        private val LOGGER = LogManager.getLogger(RemoteBackendClient::class.java)
    }

    private lateinit var group: EventLoopGroup
    private lateinit var channelType: Class<out Channel>
    private lateinit var blockingStub: CredentialServiceGrpc.CredentialServiceBlockingStub

    init {
        setChannelInfo()

        val sslContext: SslContext
        try {
            sslContext = GrpcSslContexts.forClient()
                .trustManager(ByteArrayInputStream(caCert.toByteArray(StringUtil.UTF_8)))
                .build()
        } catch (e: SSLException) {
            throw RuntimeException(e)
        }

        blockingStub = CredentialServiceGrpc.newBlockingStub(
            NettyChannelBuilder.forAddress(DomainSocketAddress(socketFile))
                .eventLoopGroup(group)
                .channelType(channelType)
                .negotiationType(NegotiationType.PLAINTEXT)
                .keepAliveTime(DEFAULT_KEEPALIVE_TIMEOUT_NANOS, TimeUnit.NANOSECONDS)
                .useTransportSecurity()
                .sslContext(sslContext)
                .overrideAuthority(host)
                .build())

        LOGGER.info("using socket file $socketFile")
    }

    fun getNVersionsRequest(credentialName: String, user: String, numberOfVersions: Int): GetNVersionsResponse {
        val request = GetNVersionsRequest
            .newBuilder()
            .setName(credentialName)
            .setRequester(user)
            .setNumberOfVersions(numberOfVersions)
            .build()

        return blockingStub.getNVersions(request)
    }

    fun getAllVersionsRequest(credentialName: String, user: String): GetNVersionsResponse {
        val request = GetAllVersionsRequest
            .newBuilder()
            .setName(credentialName)
            .setRequester(user)
            .build()

        return blockingStub.getAllVersions(request)
    }

    fun getByNameRequest(credentialName: String, user: String): GetResponse {
        val request = GetByNameRequest
            .newBuilder()
            .setName(credentialName)
            .setRequester(user)
            .build()

        return blockingStub.getByName(request)
    }

    fun getByIdRequest(credentialUuid: String, user: String): GetResponse {
        val request = GetByIdRequest
            .newBuilder()
            .setId(credentialUuid)
            .setRequester(user)
            .build()

        return blockingStub.getById(request)
    }

    fun findContainingNameRequest(name: String, user: String): FindResponse {
        val request = FindContainingNameRequest
            .newBuilder()
            .setName(name)
            .setRequester(user)
            .build()

        return blockingStub.findContainingName(request)
    }

    fun findStartingWithPathRequest(path: String, user: String): FindResponse {
        var adjustedPath = StringUtils.prependIfMissing(path, "/")
        adjustedPath = StringUtils.appendIfMissing(adjustedPath, "/")

        val request = FindStartingWithPathRequest
            .newBuilder()
            .setPath(adjustedPath)
            .setRequester(user)
            .build()

        return blockingStub.findStartingWithPath(request)
    }

    fun setRequest(name: String, type: String, data: ByteString, user: String, generationParameters: ByteString): SetResponse {
        val request = SetRequest
            .newBuilder()
            .setName(name)
            .setRequester(user)
            .setType(type)
            .setData(data)
            .setGenerationParameters(generationParameters)
            .build()

        return blockingStub.set(request)
    }

    fun deleteRequest(name: String, user: String) {
        val request = DeleteByNameRequest
            .newBuilder()
            .setName(name)
            .setRequester(user)
            .build()

        blockingStub.delete(request)
    }

    fun findPermissionByPathAndActor(path: String, actor: String, requester: String): PermissionsResponse {
        val request = FindPermissionByPathAndActorRequest
            .newBuilder()
            .setPath(path)
            .setActor(actor)
            .setRequester(requester)
            .build()

        return blockingStub.findPermissionByPathAndActor(request)
    }

    fun getPermissionByUUID(uuid: String, requester: String): PermissionsResponse {
        val request = GetPermissionRequest
            .newBuilder()
            .setUuid(uuid)
            .setRequester(requester)
            .build()

        return blockingStub.getPermission(request)
    }

    fun writePermissionRequest(path: String, actor: String, operations: MutableIterable<String>, requester: String): PermissionsResponse {
        val request = WritePermissionsRequest
            .newBuilder()
            .setPath(path)
            .setActor(actor)
            .addAllOperations(operations)
            .setRequester(requester)
            .build()

        return blockingStub.savePermissions(request)
    }

    fun deletePermissionByUUID(uuid: String, requester: String): PermissionsResponse {
        val request = DeletePermissionRequest
            .newBuilder()
            .setUuid(uuid)
            .setRequester(requester)
            .build()

        return blockingStub.deletePermission(request)
    }

    fun putPermissionRequest(uuid: String, path: String, actor: String, operations: MutableIterable<String>, requester: String): PermissionsResponse {
        val request = PutPermissionsRequest
            .newBuilder()
            .setUuid(uuid)
            .setActor(actor)
            .setPath(path)
            .addAllOperations(operations)
            .setRequester(requester)
            .build()

        return blockingStub.putPermissions(request)
    }

    fun patchPermissionRequest(uuid: String, operations: MutableIterable<String>, requester: String): PermissionsResponse {
        val request = PatchPermissionsRequest
            .newBuilder()
            .setUuid(uuid)
            .addAllOperations(operations)
            .setRequester(requester)
            .build()

        return blockingStub.patchPermissions(request)
    }

    private fun setChannelInfo() {
        when {
            Epoll.isAvailable() -> {
                group = EpollEventLoopGroup()
                channelType = EpollDomainSocketChannel::class.java
                LOGGER.info("Using epoll for Netty transport.")
            }
            KQueue.isAvailable() -> {
                group = KQueueEventLoopGroup()
                channelType = KQueueDomainSocketChannel::class.java
                LOGGER.info("Using KQueue for Netty transport.")
            }
            else -> {
                throw RuntimeException("Unsupported OS '" + System.getProperty("os.name") + "', only Unix and Mac are supported")
            }
        }
    }
}
