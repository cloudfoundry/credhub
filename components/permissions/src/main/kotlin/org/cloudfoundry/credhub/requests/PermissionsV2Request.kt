package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import org.apache.commons.lang3.StringUtils
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.PermissionOperation
import org.springframework.validation.annotation.Validated
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern

@JsonAutoDetect
@Validated
class PermissionsV2Request {
    companion object {
        const val HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH = "^(/|(?>(?:/?[^/]+))*)$"
        const val ONLY_VALID_CHARACTERS_IN_PATH = "^[a-zA-Z0-9-_/.:,()\\[\\]+]*(/\\*)?$"
        const val IS_NOT_EMPTY = "^(.|\n){2,}$"
    }

    @NotNull(message = ErrorMessages.Permissions.MISSING_PATH)
    @Pattern.List(
        Pattern(regexp = HAS_NO_DOUBLE_SLASHES_AND_DOES_NOT_END_WITH_A_SLASH, message = ErrorMessages.Permissions.INVALID_SLASH_IN_PATH),
        Pattern(regexp = ONLY_VALID_CHARACTERS_IN_PATH, message = ErrorMessages.Permissions.INVALID_CHARACTER_IN_PATH),
        Pattern(regexp = IS_NOT_EMPTY, message = ErrorMessages.Permissions.MISSING_PATH),
    )
    private lateinit var path: String

    @NotEmpty(message = ErrorMessages.Permissions.MISSING_ACTOR)
    final lateinit var actor: String

    @NotEmpty(message = ErrorMessages.Permissions.MISSING_OPERATIONS)
    final lateinit var operations: MutableList<PermissionOperation>

    constructor() : super() {
        // this needs to be there for jackson to be happy
    }

    constructor(path: String, actor: String, operations: MutableList<PermissionOperation>) : super() {
        this.path = path
        this.actor = actor
        this.operations = operations
    }

    fun getPath(): String = path

    fun setPath(path: String) {
        this.path = StringUtils.prependIfMissing(path, "/")
    }
}
