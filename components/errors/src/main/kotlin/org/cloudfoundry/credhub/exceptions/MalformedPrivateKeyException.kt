package org.cloudfoundry.credhub.exceptions

class MalformedPrivateKeyException : RuntimeException {
    constructor(messageCode: String) : super(messageCode) {}

    constructor() : super() {}
}
