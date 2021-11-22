package com.tasks.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
@Order(Ordered.HIGHEST_PRECEDENCE)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
        
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        
        http.authorizeRequests()
            .antMatchers(HttpMethod.GET,  "/swagger-ui.html").permitAll()
            .antMatchers(HttpMethod.GET,  "/swagger-resources/**").permitAll()
            .antMatchers(HttpMethod.GET,  "/v2/api-docs").permitAll()

            // ENDPOINT /projects
                .antMatchers(HttpMethod.POST,  "/api/projects").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,  "/api/projects/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,  "/api/projects/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,  "/api/projects/{id}/tasks").permitAll()


            // ENDPOINT /tasks
                .antMatchers(HttpMethod.POST,  "/api/tasks").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,  "/api/tasks/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,  "/api/tasks/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST,  "/tasks/{id}/changeState").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST,  "/tasks/{id}/changeResolution").hasRole("USER")
                .antMatchers(HttpMethod.POST,  "/tasks/{id}/changeProgress").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.POST,  "/comments").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.GET,  "/comments/{id}").hasAnyRole("USER","ADMIN")


            // ENDPOINT /users
                .antMatchers(HttpMethod.GET,  "/api/users").hasRole("ADMIN")

                .anyRequest().permitAll();

        //b2 ?¿?
        //b3 permitAll a los 3 endpoints que dice enunciado
        //b4 resto de enpoints check si tienen rol, si no anyRequest().denyAll

        //3 endpoint.hasRole("role") o en el endpoint anotacion @PreAuthorize("hasRole('ROLE_ADMIN')") tb vale @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
        //3 check en entidades p.e @PreAuthorize o @PostAuthorize( obj.user == authentication.user ) //check admin borre sus vainas

        //b1,b5
        http.addFilter( new JwtAuthorizationFilter(this.tokenProvider, customAuthenticationManager()))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }
    
    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }

}
