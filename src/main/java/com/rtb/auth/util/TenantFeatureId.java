package com.rtb.auth.util;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.Objects;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TenantFeatureId implements Serializable {
  private Long tenantId;
  private Long featureId;

  @Override
  public int hashCode() {
    return Objects.hash(tenantId, featureId);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    TenantFeatureId that = (TenantFeatureId) obj;
    return Objects.equals(tenantId, that.tenantId)
      && Objects.equals(featureId, that.featureId);
  }
}
