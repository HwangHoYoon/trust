package com.fast.trust.ai.dto;

import java.time.LocalDateTime;
import java.util.List;

public record AiRstDto(
        // 🔗 어떤 취약점의 분석인지
        Long scanDetailId,
        // 취약점 설명 (한국어)
        String description,
        // 영향 범위 설명
        String impact,
        // api_leak | exposure | misconfig | cve | privacy_risk
        String category,
        // 취약한 코드 예시
        String beforeCode,
        // 수정된 코드
        String afterCode,
        // 단계별 수정 가이드
        List<String> fixSteps,
        // simple | moderate | complex
        String fixComplexity,
        // 참고 링크
        List<String> references,
        String aiModel,
        Double confidence,
        LocalDateTime analyzedAt,
        // 디버깅용 (선택)
        String rawResponse
) {
}
