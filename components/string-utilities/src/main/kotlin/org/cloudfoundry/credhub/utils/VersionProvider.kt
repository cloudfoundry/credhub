package org.cloudfoundry.credhub.utils

import java.io.IOException
import org.springframework.stereotype.Component

@Component
class VersionProvider(resources: ResourceReader) {
    final var version: String = try {
        resources.readFileToString("version").trim { it <= ' ' }
    } catch (e: IOException) {
        "0.0.0"
    } catch (e: IllegalArgumentException) {
        "0.0.0"
    }

    fun currentVersion(): String {
        return version
    }
}
