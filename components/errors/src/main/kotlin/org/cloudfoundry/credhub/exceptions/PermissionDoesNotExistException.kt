package org.cloudfoundry.credhub.exceptions

class PermissionDoesNotExistException(
    messageCode: String,
) : RuntimeException(messageCode)
