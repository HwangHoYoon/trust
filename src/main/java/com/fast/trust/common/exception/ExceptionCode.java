package com.fast.trust.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@ToString
@AllArgsConstructor
public enum ExceptionCode {
    BAD_REQUEST(String.valueOf(HttpStatus.BAD_REQUEST.value()), "잘못된 요청입니다."),

    NOT_FOUND(String.valueOf(HttpStatus.NOT_FOUND.value()), "요청한 페이지를 찾을 수 없습니다."),

    SERVER_ERROR(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()), "내부 서버 오류입니다.");

    private static final ExceptionCode[] VALUES;

    static {
        VALUES = values();
    }

    private final String code;
    private final String message;

    public static ExceptionCode resolve(String statusCode) {
        for (ExceptionCode status : VALUES) {
            if (status.code.equals(statusCode)) {
                return status;
            }
        }
        return null;
    }
}
