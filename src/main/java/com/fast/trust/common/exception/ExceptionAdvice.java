package com.fast.trust.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ExceptionAdvice {

    //    @ExceptionHandler(value = {NoUserExistException.class, WrongPasswordException.class})
    @ExceptionHandler(CommonException.class)
    public ResponseEntity<CommonException> handleCommonException(CommonException e) {
        log.error("CommonException({}) - {}", e.getClass().getSimpleName(), e.getMessage());
        return ResponseEntity
                .status(400)
                .body(e);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<CommonException> handleException(Exception e) {
        log.error("Exception({}) - {}", e.getClass().getSimpleName(), e.getMessage());
        return ResponseEntity
                .status(400)
                .body(new CommonException(ExceptionCode.SERVER_ERROR.getMessage(), ExceptionCode.SERVER_ERROR.getCode()));
    }
}
