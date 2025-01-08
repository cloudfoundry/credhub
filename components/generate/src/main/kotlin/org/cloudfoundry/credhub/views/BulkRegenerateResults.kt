package org.cloudfoundry.credhub.views

import com.fasterxml.jackson.annotation.JsonAutoDetect

@JsonAutoDetect
class BulkRegenerateResults {
    private lateinit var regeneratedCredentials: Set<String>

    fun getRegeneratedCredentials(): Set<String> = this.regeneratedCredentials

    fun setRegeneratedCredentials(regeneratedCredentials: Set<String>) {
        this.regeneratedCredentials = regeneratedCredentials
    }
}
