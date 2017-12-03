package org.su.plugin.security.exception;

//权限异常
public class AuthcException extends RuntimeException{
    public AuthcException(){
        super();
    }

    public AuthcException(String message){
        super(message);
    }

    public AuthcException(String message, Throwable cause){
        super(message, cause);
    }

    public AuthcException(Throwable cause){
        super(cause);
    }
}
