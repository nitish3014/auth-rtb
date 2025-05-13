package com.rtb.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class FeatureDTO {
  private Long id;
  private String featureName;
  private String featureDescription;
  private boolean enabled;

}
