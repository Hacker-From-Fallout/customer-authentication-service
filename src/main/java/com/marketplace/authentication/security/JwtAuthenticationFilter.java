package com.marketplace.authentication.security;

import java.io.IOException;
import java.util.function.Function;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import com.marketplace.authentication.domain.entities.CustomerUser;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String HEADER_NAME = "Authorization";
    public final Function<String, Token> accessTokenJwsStringDeserializer;
    public final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String authenticationHeader = request.getHeader(HEADER_NAME);

        if (StringUtils.isEmpty(authenticationHeader) || !StringUtils.startsWith(authenticationHeader, BEARER_PREFIX)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization header missing or invalid");
            SecurityContextHolder.clearContext();
            return;
        }

        String jwt = authenticationHeader.substring(BEARER_PREFIX.length());
        Token accessToken = accessTokenJwsStringDeserializer.apply(jwt);

        if (accessToken == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
            SecurityContextHolder.clearContext();
            return;
        }

        CustomerUser customerUser = (CustomerUser) userDetailsService.loadUserByUsername(accessToken.subject());

        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(customerUser, null, customerUser.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
