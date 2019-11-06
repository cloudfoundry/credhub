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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as PermissionsView?

        return EqualsBuilder()
            .append(credentialName, that!!.credentialName)
            .append(permissions, that.permissions)
            .isEquals
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(17, 37)
            .append(credentialName)
            .append(permissions)
            .toHashCode()
    }
}
