package org.cloudfoundry.credhub.utils

import com.google.common.io.Resources
import kotlin.text.Charsets.UTF_8
import org.springframework.stereotype.Component

@Component
class ResourceReader {
    fun readFileToString(fileName: String): String {
        val resource = Resources.getResource(fileName)
        return Resources.toString(resource, UTF_8)
    }
}
