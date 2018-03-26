package org.cloudfoundry.credhub.audit;

public enum OperationDeviceAction {
    GET,
    SET,
    GENERATE,
    REGENERATE,
    BULK_REGENERATE,
    DELETE,
    FIND,
    GET_PERMISSIONS,
    ADD_PERMISSION,
    DELETE_PERMISSION,
    INTERPOLATE,
    INFO,
    VERSION,
    HEALTH,
    KEY_USAGE,
    UPDATE_TRANSITIONAL_VERSION
}
