package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonAutoDetect
import org.cloudfoundry.credhub.PermissionOperation
import java.util.Objects
import java.util.UUID

@JsonAutoDetect
class PermissionsV2View {
    var path: String? = null
    var operations: List<PermissionOperation>? = null
    var actor: String? = null
    var uuid: UUID? = null

    constructor(path: String?, operations: List<PermissionOperation>?, actor: String?, uuid: UUID?) : super() {
        this.path = path
        this.operations = operations
        this.actor = actor
        this.uuid = uuid
    }

    constructor() : super() {}

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as PermissionsV2View?
        return path == that!!.path &&
            operations == that.operations &&
            actor == that.actor &&
            uuid == that.uuid
    }

    override fun hashCode(): Int = Objects.hash(path, operations, actor, uuid)
}
