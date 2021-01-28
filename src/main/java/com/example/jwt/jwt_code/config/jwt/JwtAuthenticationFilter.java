package com.example.jwt.jwt_code.config.jwt;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;



public class JwtAuthenticationFilter extends OncePerRequestFilter {

  @Autowired
  private JwtTokenUtil jwtTokenUtil;

  // public static final String TOKEN_PREFIX = "Bearer";
  public static final String HEADER_STRING = "Authorization";

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    String header = req.getHeader(HEADER_STRING);
    String userId = null;
    String authToken = null;
     if (header != null) { // && header.startsWith(TOKEN_PREFIX)) {
      // authToken = header.replace(TOKEN_PREFIX,"").trim();
      authToken = header;

      try {
        userId = jwtTokenUtil.getUserIdFromToken(authToken);
      } catch (Exception e) {
        logger.error("Exception", e);
      }
     } else {
       logger.warn("couldn't find bearer string, will ignore the header");
     }
    if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {

      if (jwtTokenUtil.validateToken(authToken)) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authToken, null,
            Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
        logger.info("authenticated user " + userId + ", setting security context");
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    }

    chain.doFilter(req, res);
  }
}
