package com.fast.trust.common.exception;

import lombok.Getter;

@Getter
public class CommonException extends RuntimeException {

    private final String errorCode;

    public CommonException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public CommonException(String message, Throwable cause, String errorCode) {
        super(message, cause);
        this.errorCode = errorCode;
    }

}
