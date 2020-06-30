package org.cloudfoundry.credhub.audit.entities

import org.apache.commons.lang3.builder.EqualsBuilder
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails
import java.util.Objects

class GetCredential : RequestDetails {
    var name: String? = null
    var versions: Int? = null
    var current: Boolean? = null

    constructor(credentialName: String, numberOfVersions: Int?, current: Boolean) : super() {
        name = credentialName
        versions = numberOfVersions
        this.current = current
    }

    constructor() : super() {
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as GetCredential?

        return EqualsBuilder()
            .append(name, that!!.name)
            .append(versions, that.versions)
            .append(current, that.current)
            .isEquals
    }

    override fun hashCode(): Int {
        return Objects.hash(name, versions, current)
    }

    override fun operation(): OperationDeviceAction {
        return OperationDeviceAction.GET
    }
}
