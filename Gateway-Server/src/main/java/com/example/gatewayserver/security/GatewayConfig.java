package com.example.gatewayserver.security;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {
    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder){
        return builder.routes()
                .route(r->
                        r.path("/image/**")
                                .uri("lb://IMAGE-SERVICE")
                )
                .route(r1->
                        r1.path("/auth/**")
                                .uri("lb://AUTH-SERVER")
                )
                .build();
    }
}
