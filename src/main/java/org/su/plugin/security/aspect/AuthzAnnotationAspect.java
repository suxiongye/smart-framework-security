package org.su.plugin.security.aspect;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.su.framework.annotation.Aspect;
import org.su.framework.annotation.Controller;
import org.su.framework.proxy.AspectProxy;
import org.su.plugin.security.annotation.User;
import org.su.plugin.security.exception.AuthcException;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

//授权注解切面
@Aspect(Controller.class)
public class AuthzAnnotationAspect extends AspectProxy{
    //定义一个基于授权功能的注解类数组
    private static final Class[] ANNOTATION_CLASS_ARRAY={
            User.class
    };


    @Override
    public void before(Class<?> cls, Method method, Object[] params) throws Throwable {
        //从目标类和目标方法中获取响应注解
        Annotation annotation = getAnnotation(cls, method);
        if (annotation != null){
             //判断注解类型
            Class<?> annotationType = annotation.annotationType();
            if (annotationType.equals(User.class)){
                handleUser();
            }
        }

    }

    //获取对应注解
    private Annotation getAnnotation(Class<?> cls, Method method){
        //遍历所有授权注解
        for (Class<? extends Annotation> annotationClass : ANNOTATION_CLASS_ARRAY){
            //判断方法上是否有注解
            if (method.isAnnotationPresent(annotationClass)){
                return method.getAnnotation(annotationClass);
            }
            //判断目标类是否有该注解
            if (cls.isAnnotationPresent(annotationClass)){
                return cls.getAnnotation(annotationClass);
            }
        }
        //若方法和类都没有，则返回空对象
        return null;
    }

    //处理未登录情况
    private void handleUser(){
        Subject currentUser = SecurityUtils.getSubject();
        PrincipalCollection principalCollection = currentUser.getPrincipals();
        if (principalCollection == null || principalCollection.isEmpty()){
            throw new AuthcException("当前用户未登录");
        }
    }
}
