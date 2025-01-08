package org.cloudfoundry.credhub.exceptions

class PermissionInvalidPathAndActorException(
    messageCode: String,
) : RuntimeException(messageCode)
