package io.pivotal.security.entity;

import static io.pivotal.security.constants.UuidConstants.UUID_BYTES;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.util.UUID;

@Entity
@Table(name = "AccessEntry")
public class AccessEntryData {

    @Id
    @Column(length = UUID_BYTES, columnDefinition = "VARBINARY")
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    private UUID uuid;

    @ManyToOne
    @JoinColumn(name = "secret_name_uuid", nullable = false)
    private SecretName resource;

    @Column(nullable = false)
    private String actor;

    @Column(name = "read_permission", nullable = false)
    private Boolean readPermission;

    @Column(name = "write_permission",nullable = false)
    private Boolean writePermission;

    public AccessEntryData(SecretName resource, String actor, Boolean readPermission, Boolean writePermission) {
        this.resource = resource;
        this.actor = actor;
        this.readPermission = readPermission;
        this.writePermission = writePermission;
    }

    @SuppressWarnings("unused")
    public AccessEntryData() {
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public SecretName getResource() {
        return resource;
    }

    public void setResource(SecretName resource) {
        this.resource = resource;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public Boolean getReadPermission() {
        return readPermission;
    }

    public void setReadPermission(Boolean readPermission) {
        this.readPermission = readPermission;
    }

    public Boolean getWritePermission() {
        return writePermission;
    }

    public void setWritePermission(Boolean writePermission) {
        this.writePermission = writePermission;
    }
}
