package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import com.google.common.collect.Lists
import jakarta.validation.constraints.NotEmpty
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.springframework.validation.annotation.Validated

@JsonAutoDetect
@Validated
class PermissionEntry {
    @NotEmpty(message = ErrorMessages.Permissions.MISSING_ACTOR)
    var actor: String? = null

    @NotEmpty(message = ErrorMessages.Permissions.MISSING_PATH)
    var path: String? = null

    @NotEmpty(message = ErrorMessages.Permissions.MISSING_OPERATIONS)
    @JsonProperty("operations")
    var allowedOperations: List<PermissionOperation>? = null

    constructor() : super() {}

    constructor(actor: String, path: String, vararg operations: PermissionOperation) : this(
        actor,
        path,
        Lists.newArrayList<PermissionOperation>(*operations),
    ) {
    }

    constructor(actor: String, path: String?, operations: List<PermissionOperation>) : super() {
        this.actor = actor
        this.path = path
        this.allowedOperations = operations
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as PermissionEntry?

        return EqualsBuilder()
            .append(actor, that!!.actor)
            .append(path, that.path)
            .append(allowedOperations, that.allowedOperations)
            .isEquals
    }

    override fun hashCode(): Int =
        HashCodeBuilder(17, 37)
            .append(actor)
            .append(path)
            .append(allowedOperations)
            .toHashCode()
}
