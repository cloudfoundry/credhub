package org.cloudfoundry.credhub

class Management {
    var readOnlyMode: Boolean = false

    constructor() : super() {
        // no arg constructor required by Jackson
    }

    constructor(readOnlyMode: Boolean?) : super() {
        this.readOnlyMode = readOnlyMode!!
    }

    override fun toString(): String {
        return "isReadOnly: $readOnlyMode"
    }
}
