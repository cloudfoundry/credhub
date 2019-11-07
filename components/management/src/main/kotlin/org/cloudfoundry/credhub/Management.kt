package org.cloudfoundry.credhub

class Management {
    var isReadOnlyMode: Boolean = false

    constructor() : super() {
        // no arg constructor required by Jackson
    }

    constructor(readOnlyMode: Boolean?) : super() {
        this.isReadOnlyMode = readOnlyMode!!
    }

    override fun toString(): String {
        return "isReadOnly: $isReadOnlyMode"
    }
}
