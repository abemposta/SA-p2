package com.tasks.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, order = 1)
@EnableTransactionManagement(order = 0)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
        
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/webjars/**")
                .antMatchers("/application/**")
                .antMatchers("/css/**")
                .antMatchers("/javascript-libs/noty/**")
                .antMatchers("/react-libs/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        
        http.authorizeRequests()
            .antMatchers(HttpMethod.GET,  "/swagger-ui.html").permitAll()
            .antMatchers(HttpMethod.GET,  "/swagger-resources/**").permitAll()
            .antMatchers(HttpMethod.GET,  "/v2/api-docs").permitAll()

                //b3
                .antMatchers(HttpMethod.GET,  "/dashboard/").permitAll()
                .antMatchers(HttpMethod.POST, "/api/login").permitAll()
                .antMatchers(HttpMethod.GET,  "/api/projects").permitAll()
                .antMatchers(HttpMethod.GET,  "/api/projects/{id}").permitAll()
                .antMatchers(HttpMethod.GET,  "/api/projects/{id}/tasks").permitAll()
                .antMatchers(HttpMethod.GET,  "/api/comments/{id}").permitAll()
                .antMatchers(HttpMethod.GET,  "/api/tasks").permitAll()
                .antMatchers(HttpMethod.GET,  "/api/task/{id}").permitAll()


                // ENDPOINT /projects c)+b4)
                .antMatchers(HttpMethod.POST,  "/api/projects/").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,  "/api/projects/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,  "/api/projects/{id}").hasRole("ADMIN")

            // ENDPOINT /tasks c)+b4)
                .antMatchers(HttpMethod.POST,  "/api/tasks/").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,  "/api/tasks/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,  "/api/tasks/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST,  "/tasks/{id}/changeState/").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST,  "/tasks/{id}/changeResolution/").hasRole("USER")
                .antMatchers(HttpMethod.POST,  "/tasks/{id}/changeProgress/").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.POST,  "/comments/").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.GET,  "/comments/{id}").hasAnyRole("USER","ADMIN")


            // ENDPOINT /users c)+b4)
                .antMatchers(HttpMethod.GET,  "/api/users/").hasRole("ADMIN")
                .anyRequest().denyAll();


        //3 ch
        // eck en entidades p.e @PreAuthorize o @PostAuthorize( obj.user == authentication.user ) //check admin borre sus vainas

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
