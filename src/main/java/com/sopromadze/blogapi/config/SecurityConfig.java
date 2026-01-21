package com.sopromadze.blogapi.config;

import com.sopromadze.blogapi.repository.UserRepository;
import com.sopromadze.blogapi.security.JwtAuthenticationEntryPoint;
import com.sopromadze.blogapi.security.JwtAuthenticationFilter;
import com.sopromadze.blogapi.service.impl.CustomUserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		securedEnabled = true,
		jsr250Enabled = true,
		prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private final CustomUserDetailsServiceImpl customUserDetailsService;
	private final JwtAuthenticationEntryPoint unauthorizedHandler;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	@Autowired
	public SecurityConfig(UserRepository userRepository, CustomUserDetailsServiceImpl customUserDetailsService,
						  JwtAuthenticationEntryPoint unauthorizedHandler, JwtAuthenticationFilter jwtAuthenticationFilter) {
		this.customUserDetailsService = customUserDetailsService;
		this.unauthorizedHandler = unauthorizedHandler;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.cors().configurationSource(corsConfigurationSource()) // 使用自定义CORS配置
				.and()
				.csrf().disable()
				.exceptionHandling()
				.authenticationEntryPoint(unauthorizedHandler)
				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.authorizeRequests()
				// 公开端点 - 不需要认证
				.antMatchers("/").permitAll()
				.antMatchers("/error").permitAll()
				.antMatchers("/favicon.ico").permitAll()
				.antMatchers("/index.html").permitAll()
				.antMatchers("/static/**").permitAll()

				// Actuator端点
				.antMatchers("/actuator/**").permitAll()

				// 认证相关端点
				.antMatchers("/api/auth/**").permitAll()

				// 公开的API端点
				.antMatchers(HttpMethod.GET, "/api/posts/**").permitAll()
				.antMatchers(HttpMethod.GET, "/api/albums/**").permitAll()
				.antMatchers(HttpMethod.GET, "/api/photos/**").permitAll()
				.antMatchers(HttpMethod.GET, "/api/comments/**").permitAll()
				.antMatchers(HttpMethod.GET, "/api/users/checkUsernameAvailability").permitAll()
				.antMatchers(HttpMethod.GET, "/api/users/checkEmailAvailability").permitAll()

				// 其他所有请求需要认证
				.anyRequest().authenticated()
				.and()
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}

	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(customUserDetailsService)
				.passwordEncoder(passwordEncoder());
	}

	@Bean(BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// CORS配置
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(
				"http://localhost:8080",
				"http://127.0.0.1:8080",
				"http://localhost:5500",
				"null"  // 允许file://协议
		));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
		configuration.setAllowedHeaders(Arrays.asList(
				"Authorization",
				"Content-Type",
				"X-Requested-With",
				"Accept",
				"Origin",
				"Access-Control-Request-Method",
				"Access-Control-Request-Headers"
		));
		configuration.setExposedHeaders(Arrays.asList(
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Credentials",
				"Authorization"
		));
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}