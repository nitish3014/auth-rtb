package com.rtb.auth.util;

import jakarta.persistence.Embeddable;

import java.io.Serializable;
import java.util.Objects;

@Embeddable
public class FeaturePermissionId implements Serializable {

    private Long featureId;
    private Long permissionId;

    // Public no-argument constructor required for JPA
    public FeaturePermissionId() {}

    // Constructor with fields
    public FeaturePermissionId(Long featureId, Long permissionId) {
        this.featureId = featureId;
        this.permissionId = permissionId;
    }

    // Getters and setters
    public Long getFeatureId() {
        return featureId;
    }

    public void setFeatureId(Long featureId) {
        this.featureId = featureId;
    }

    public Long getPermissionId() {
        return permissionId;
    }

    public void setPermissionId(Long permissionId) {
        this.permissionId = permissionId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        FeaturePermissionId that = (FeaturePermissionId) o;
        return Objects.equals(featureId, that.featureId)
                && Objects.equals(permissionId, that.permissionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(featureId, permissionId);
    }
}
