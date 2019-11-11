package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonAutoDetect
import java.util.Objects
import java.util.UUID
import org.cloudfoundry.credhub.PermissionOperation

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

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as PermissionsV2View?
        return path == that!!.path &&
            operations == that.operations &&
            actor == that.actor &&
            uuid == that.uuid
    }

    override fun hashCode(): Int {
        return Objects.hash(path, operations, actor, uuid)
    }
}
