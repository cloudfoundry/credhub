package org.cloudfoundry.credhub.data;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.h2.tools.TriggerAdapter;

/**
 * H2 trigger for credential_version record deletion
 */
public class CredentialVersionDeleteTrigger extends TriggerAdapter {
    @Override
    public void fire(Connection conn, ResultSet oldRow, ResultSet newRow)
            throws SQLException {
        try (PreparedStatement stmt = conn.prepareStatement(
                "DELETE FROM encrypted_value WHERE uuid = ?")) {
            stmt.setObject(1, oldRow.getObject("encrypted_value_uuid"));
            stmt.executeUpdate();
        }
    }
}
