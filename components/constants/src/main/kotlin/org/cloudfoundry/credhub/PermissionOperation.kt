package org.cloudfoundry.credhub

import com.fasterxml.jackson.annotation.JsonValue
import java.util.Arrays
import java.util.stream.Collectors

enum class PermissionOperation private constructor(
    @get:JsonValue
    val operation: String,
) {
    READ("read"),
    WRITE("write"),
    DELETE("delete"),
    READ_ACL("read_acl"),
    WRITE_ACL("write_acl"), ;

    companion object {
        val commaSeparatedPermissionOperations: String
            get() =
                Arrays
                    .stream(values())
                    .map<String> { it.operation }
                    .collect(Collectors.joining(", "))
    }
}
