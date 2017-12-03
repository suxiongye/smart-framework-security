package org.su.plugin.security.password;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.su.framework.util.CodecUtil;

public class Md5CredentialsMatcher implements CredentialsMatcher{
    private static final Logger LOGGER = LoggerFactory.getLogger(Md5CredentialsMatcher.class);
    //用md5进行加密并对比
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info){
        //获取从表单提交过来的未通过md5加密的密码（明文）
        String submitted = String.valueOf(((UsernamePasswordToken)token).getPassword());
        //获取数据库的密码，已通过md5加密
        String encrypted = String.valueOf(info.getCredentials());
        LOGGER.error("submitted: "+ submitted);
        LOGGER.error("submitted_md5: "+ CodecUtil.md5(submitted));
        LOGGER.error("encrypted: "+info.getCredentials().toString());
        //JdbcRealm的getCredentials有问题
        //return CodecUtil.md5(submitted).equals(encrypted);
        return submitted.equals(encrypted);
    }
}
