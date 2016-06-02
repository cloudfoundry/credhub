package io.pivotal.security.entity

import javax.persistence.*

@Entity
data class NamedSecret(
    @field:Id
    @field:GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
    var id: Long = 0,

    @field:Column(unique = true)
    var name: String = "",

    var type: String = "value",

    var value: String = ""
)