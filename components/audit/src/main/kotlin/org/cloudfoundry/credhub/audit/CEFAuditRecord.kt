package org.cloudfoundry.credhub.audit

import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.utils.VersionProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Scope
import org.springframework.context.annotation.ScopedProxyMode
import org.springframework.stereotype.Component
import org.springframework.web.context.WebApplicationContext
import java.time.Instant
import javax.servlet.http.HttpServletRequest

@Component
@Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
class CEFAuditRecord {
    // CEF Spec
    var signatureId: String? = null
    private var credhubServerVersion: String? = null

    // Data Inherited (somewhat) from CC
    var timestamp = Instant.now().toEpochMilli().toString()
    var username: String? = null
    private var userGuid: String? = null
    var authMechanism: String? = null
    var requestPath: String? = null
    var requestMethod: String? = null
    var result: String? = null
    var sourceAddress: String? = null
    var destinationAddress: String? = null
    var httpStatusCode: Int? = null
        set(httpStatusCode) {
            field = httpStatusCode
            this.result = HttpUtils.getResultCode(httpStatusCode!!)
        }

    // CredHub-specific Data
    var resourceName: String? = null
    var resourceUUID: String? = null
    var versionUUID: String? = null
    var operation: OperationDeviceAction? = null
    var requestDetails: RequestDetails? = null
        set(requestDetails) {
            field = requestDetails
            this.operation = requestDetails!!.operation()
        }
    var resourceList: MutableList<Resource>? = null
    private var versionList: MutableList<Version>? = null

    @Autowired
    constructor(versionProvider: VersionProvider) : super() {
        this.setCredhubServerVersion(versionProvider.currentVersion())
    }

    constructor() : super()

    override fun toString(): String {
        if (resourceList == null || resourceList!!.isEmpty()) {
            return logRecord().toString()
        }

        val builder = StringBuilder()
        for (i in resourceList!!.indices) {
            if (i > 0) {
                builder.append(System.getProperty("line.separator"))
            }
            this.resourceName = resourceList!![i].resourceName
            this.resourceUUID = resourceList!![i].resourceId
            if (versionList != null && versionList!!.isNotEmpty()) {
                this.versionUUID = versionList!![i].versionId
            }
            builder.append(logRecord())
        }

        return builder.toString()
    }

    private fun logRecord(): StringBuilder {
        val capacityEstimate = 200
        val builder = StringBuilder(capacityEstimate)

        val severity = "0"
        val cefVersion = "0"
        val deviceVendor = "cloud_foundry"
        val deviceProduct = "credhub"

        builder
            .append("CEF:")
            .append(cefVersion)
            .append('|')
            .append(deviceVendor)
            .append('|')
            .append(deviceProduct)
            .append('|')
            .append(credhubServerVersion)
            .append('|')
            .append(signatureId)
            .append('|')
            .append(signatureId)
            .append('|')
            .append(severity)
            .append('|')
            .append("rt=")
            .append(timestamp)
            .append(' ')
            .append("suser=")
            .append(username)
            .append(' ')
            .append("suid=")
            .append(userGuid)
            .append(' ')
            .append("cs1Label=")
            .append("userAuthenticationMechanism")
            .append(' ')
            .append("cs1=")
            .append(authMechanism)
            .append(' ')
            .append("request=")
            .append(requestPath)
            .append(' ')
            .append("requestMethod=")
            .append(requestMethod)
            .append(' ')
            .append("cs3Label=")
            .append("versionUuid")
            .append(' ')
            .append("cs3=")
            .append(versionUUID)
            .append(' ')
            .append("cs4Label=")
            .append("httpStatusCode")
            .append(' ')
            .append("cs4=")
            .append(this.httpStatusCode)
            .append(' ')
            .append("src=")
            .append(sourceAddress)
            .append(' ')
            .append("dst=")
            .append(destinationAddress)
            .append(' ')
            .append("cs2Label=")
            .append("resourceName")
            .append(' ')
            .append("cs2=")
            .append(resourceName)
            .append(' ')
            .append("cs5Label=")
            .append("resourceUuid")
            .append(' ')
            .append("cs5=")
            .append(resourceUUID)
            .append(' ')
            .append("deviceAction=")
            .append(operation)
            .append(' ')
        if (this.requestDetails != null) {
            builder
                .append("cs6Label=")
                .append("requestDetails")
                .append(' ')
                .append("cs6=")
                .append(this.requestDetails!!.toJSON())
                .append(' ')
        }
        return builder
    }

    fun setHttpRequest(request: HttpServletRequest) {
        val pathQuery = StringBuilder(request.requestURI)

        if (!StringUtils.isEmpty(request.queryString)) {
            pathQuery.append('?').append(request.queryString)
        }

        sourceAddress = request.getHeader("X-FORWARDED-FOR") ?: request.remoteAddr

        requestPath = pathQuery.toString()
        requestMethod = request.method
        signatureId = String.format("%s %s", request.method, request.requestURI)
        destinationAddress = request.serverName
    }

    fun setCredhubServerVersion(credhubServerVersion: String) {
        this.credhubServerVersion = credhubServerVersion
    }

    fun setUserGuid(userGuid: String) {
        this.userGuid = userGuid
    }

    fun setResource(credential: AuditableCredential?) {
        if (credential?.uuid == null) {
            return
        }

        this.resourceName = credential.name!!
        this.resourceUUID = credential.uuid!!.toString()
    }

    fun setResource(data: AuditablePermissionData?) {
        if (data?.uuid == null) {
            return
        }

        this.resourceName = data.path!!
        this.resourceUUID = data.uuid!!.toString()
    }

    fun setVersion(credentialVersion: AuditableCredentialVersion?) {
        if (credentialVersion?.uuid == null) {
            return
        }

        this.versionUUID = credentialVersion.uuid!!.toString()
    }

    fun addResource(credential: AuditableCredential?) {
        initResourceList()

        if (credential != null) {
            this.resourceList!!.add(Resource(credential.name!!, credential.uuid!!.toString()))
        }
    }

    fun addResource(permissionData: AuditablePermissionData?) {
        initResourceList()

        if (permissionData != null) {
            this.resourceList!!.add(Resource(permissionData.path!!, permissionData.uuid!!.toString()))
        }
    }

    fun addVersion(credentialVersion: AuditableCredentialVersion?) {
        if (versionList == null) {
            versionList = ArrayList()
        }

        if (credentialVersion != null) {
            this.versionList!!.add(Version(credentialVersion.uuid!!.toString()))
        }
    }

    fun initCredentials() {
        this.resourceList = ArrayList()
        this.versionList = ArrayList()
    }

    fun addAllVersions(credentialVersions: List<AuditableCredentialVersion>) {
        credentialVersions.forEach { i -> addVersion(i) }
    }

    fun addAllResources(permissionData: List<AuditablePermissionData>) {
        permissionData.forEach { i -> addResource(i) }
    }

    fun addAllCredentials(list: List<AuditableCredential>) {
        list.forEach { i -> this.addResource(i) }
    }

    private fun initResourceList() {
        if (resourceList == null) {
            resourceList = ArrayList()
        }
    }

    fun getVersionList(): List<Version>? = versionList
}
