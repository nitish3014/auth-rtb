package com.rtb.auth.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping(value = "/api/v1/auth/{tenantId}/")
public abstract class BaseController {

  protected Integer getTenantId(@PathVariable("tenantId") Integer tenantId) {
    return tenantId;
  }

}