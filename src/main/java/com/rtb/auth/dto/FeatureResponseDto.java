package com.rtb.auth.dto;

import lombok.Data;

import java.util.List;
import java.util.Set;

@Data
public class FeatureResponseDto {

    private Set<FeatureDTO> features;
    private List<String> permissions;

    public FeatureResponseDto(Set<FeatureDTO> features, List<String> permissions) {
        this.features = features;
        this.permissions = permissions;
    }
}
