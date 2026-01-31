package com.fast.trust.scan.dto;

public record ScanReqDto(
        // 스캔할 대상 URL (예: https://example.com)
        String targetUrl,
        // 스캔 모드 (예: "full", "critical")
         String mode,
         // 선택 사항: 특정 템플릿만 지정하고 싶은 경우
         String templates
) {}
