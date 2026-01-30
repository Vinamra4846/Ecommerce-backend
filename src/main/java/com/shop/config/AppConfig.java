// package com.shop.config;

// import java.util.Arrays;
// import java.util.Collections;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.http.HttpMethod;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
// import org.springframework.web.cors.CorsConfiguration;
// import org.springframework.web.cors.CorsConfigurationSource;

// import jakarta.servlet.http.HttpServletRequest;
// import com.shop.config.JwtTokenValidator;
// @Configuration
// public class AppConfig {
	
// 	@Bean
// 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
// 		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
// 		.and()
// 		.authorizeHttpRequests(Authorize -> Authorize
// 				.requestMatchers("/api/**").authenticated()
// 				.anyRequest().permitAll()
// 				)
// 		.addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class)
// 		.csrf().disable()
// 		.cors().configurationSource(new CorsConfigurationSource() {
					
// 					@Override
// 					public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
						
// 						CorsConfiguration cfg = new CorsConfiguration();
						
// 						cfg.setAllowedOrigins(Arrays.asList(
								
// 								"http://localhost:3000", 
// 								"http://localhost:4000",
// 							"https://ecommerce-shop-sphere-5xmsqnhkv-vinamra4847-3897s-projects.vercel.app"
								
								
								
// 							)
// 						);
// 						cfg.setAllowedMethods(Arrays.asList("GET", "POST","DELETE","PUT"));
// 						cfg.setAllowedMethods(Collections.singletonList("*"));
// 						cfg.setAllowCredentials(true);
// 						cfg.setAllowedHeaders(Collections.singletonList("*"));
// 						cfg.setExposedHeaders(Arrays.asList("Authorization"));
// 						cfg.setMaxAge(3600L);
// 						return cfg;
						
// 					}
// 				})
// 		.and()
// 		.httpBasic()
// 		.and()
// 		.formLogin();
		
// 		return http.build();
		
// 	}
	
// 	@Bean
// 	public PasswordEncoder passwordEncoder() {
// 		return new BCryptPasswordEncoder();
// 	}

// }

package com.shop.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class AppConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JwtTokenValidator(),
                    UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOriginPatterns(List.of(
            "http://localhost:3000",
            "http://localhost:4000",
            "https://ecommerce-shop-sphere-ckmjw5sm1-vinamra4847-3897s-projects.vercel.app" 
								
        ));

        config.setAllowedMethods(List.of(
            "GET", "POST", "PUT", "DELETE", "OPTIONS"
        ));

        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

