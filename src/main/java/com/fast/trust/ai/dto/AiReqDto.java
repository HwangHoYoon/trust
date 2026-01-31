package com.fast.trust.ai.dto;

import java.util.List;

public record AiReqDto(
        // ScanDetail.id
        String id,

        // nuclei template-id
        String templateId,

        // 취약점 이름
        String name,

        // info, low, medium, high, critical
        String severity,

        // 발견 위치 (URL, path 등)
        String matchedAt,

        // nuclei extracted_results
        List<String> extractedResults
) {
}
