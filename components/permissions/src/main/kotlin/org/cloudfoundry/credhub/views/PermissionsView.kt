package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonAutoDetect
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.cloudfoundry.credhub.requests.PermissionEntry

@JsonAutoDetect
class PermissionsView {
    var credentialName: String? = null
    var permissions: List<PermissionEntry>? = null

    constructor() : super() {}

    constructor(credentialName: String, permissions: List<PermissionEntry>) : super() {
        this.credentialName = credentialName
        this.permissions = permissions
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as PermissionsView?

        return EqualsBuilder()
            .append(credentialName, that!!.credentialName)
            .append(permissions, that.permissions)
            .isEquals
    }

    override fun hashCode(): Int =
        HashCodeBuilder(17, 37)
            .append(credentialName)
            .append(permissions)
            .toHashCode()
}
