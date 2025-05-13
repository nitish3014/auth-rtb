package com.rtb.auth.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.util.List;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ConfigCtrl implements Filter {
  private static final List<String> ALLOWED_ORIGINS = List.of(
          "https://portal.mvpin90days.com",
          "https://dev.portal.mvpin90days.com",
          "http://localhost:5000",
          "https://webapp-dev.mvpin90days.webknot-dev.in",
          "https://webapp.mvpin90days.com"
  );

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
          throws IOException, ServletException {

    HttpServletResponse response = (HttpServletResponse) res;
    HttpServletRequest request = (HttpServletRequest) req;

    String origin = request.getHeader("Origin");

    if (origin != null && ALLOWED_ORIGINS.contains(origin)) {
      response.setHeader("Access-Control-Allow-Origin", origin);
      response.setHeader("Access-Control-Allow-Credentials", "true");
    }

    response.setHeader("Access-Control-Allow-Methods",
            "POST, PUT, GET, PATCH, OPTIONS, DELETE");
    response.setHeader("Access-Control-Allow-Headers",
            "Authorization, Content-Type, X-Insights-Data, Set-Cookie");
    response.setHeader("Access-Control-Max-Age", "3600");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
    response.setHeader("Content-Security-Policy", 
      "default-src 'self'; script-src 'self' https://trusted-cdn.com;"
      + " style-src 'self' 'unsafe-inline'; img-src 'self' data:;" 
      + " font-src 'self' https://fonts.googleapis.com;");

    if ("OPTIONS".equalsIgnoreCase(((HttpServletRequest) req).getMethod())) {
      response.setStatus(HttpServletResponse.SC_OK);
    } else {
      chain.doFilter(req, res);
    }
  }
  @Override
  public void destroy() {
  }
  @Override
  public void init(FilterConfig config) throws ServletException {
  }

}

