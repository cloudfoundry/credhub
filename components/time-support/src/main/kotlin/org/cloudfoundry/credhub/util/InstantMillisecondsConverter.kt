package org.cloudfoundry.credhub.util

import java.time.Instant
import javax.persistence.AttributeConverter

class InstantMillisecondsConverter : AttributeConverter<Instant, Long> {
    override fun convertToDatabaseColumn(attribute: Instant): Long? = attribute.toEpochMilli()

    override fun convertToEntityAttribute(dbData: Long?): Instant = Instant.ofEpochMilli(dbData!!)
}
