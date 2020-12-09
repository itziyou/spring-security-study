package com.iuvya.springsecuritystudy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author ziyou
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        // 不对密码进行加密，明文存储
        return NoOpPasswordEncoder.getInstance();
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        // 用来配置忽略掉的 URL 地址，一般对于静态文件，我们可以采用此操作。
        web.ignoring().antMatchers("/js/**", "/css/**","/images/**");
    }

    /**
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")
                //.loginProcessingUrl("/doLogin")
                //.usernameParameter("name")
                //.passwordParameter("pwd")
                //
                .defaultSuccessUrl("/index")
                // successForwardUrl 表示不管你是从哪里来的，登录后一律跳转到 successForwardUrl 指定的地址
                //.successForwardUrl("/index")
                .failureForwardUrl("/errorMsg")
                //.failureUrl("/errorMsg")
                .permitAll()
                .and()
                .logout()
/*                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))
                // 表示注销成功后要跳转的页面。
                .logoutSuccessUrl("/index")
                // deleteCookies 用来清除 cookie。
                .deleteCookies()
                // clearAuthentication 和 invalidateHttpSession 分别表示清除认证信息和使 HttpSession 失效，默认可以不用配置，默认就会清除
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .permitAll()*/
                .and()
                .csrf().disable();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("123").roles("admin");
    }
}
