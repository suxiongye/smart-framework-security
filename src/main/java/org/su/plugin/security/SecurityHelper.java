package org.su.plugin.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.su.plugin.security.exception.AuthcException;

import java.security.Security;

public final class SecurityHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(Security.class);
    //登陆
    public static void login(String username, String password) throws AuthcException{
        Subject currentUser = SecurityUtils.getSubject();
        if (currentUser != null){
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            try {
                currentUser.login(token);
            }catch (AuthenticationException e){
                LOGGER.error("login failure", e);
                throw new AuthcException(e);
            }
        }
    }

    //注销
    public static void logout(){
        Subject currentUser = SecurityUtils.getSubject();
        if (currentUser != null){
            currentUser.logout();
        }
    }
}
