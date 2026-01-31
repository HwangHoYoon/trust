package com.fast.trust.scan.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "scan_detail")
public class ScanDetail {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private String scanId;

    @Column(name = "template_id")
    private String templateId;

    @Column(name = "name")
    private String name;

    @Column(name = "severity")
    private String severity;

    @Column(name = "matched_at")
    private String matchedAt;

    // Nuclei 스캔 원본 결과 (jsonb)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "full_result", columnDefinition = "jsonb")
    private Map<String, Object> fullResult;

    // 추출된 데이터 (extractedResults)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "extracted_results", columnDefinition = "jsonb")
    private List<String> extractedResults;

    // 태그
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "tags", columnDefinition = "jsonb")
    private List<String> tags;

    // AI 분석 결과
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ai_result", columnDefinition = "jsonb")
    private Map<String, Object> aiResult;

    @Column(name = "ai_analyzed")
    private boolean aiAnalyzed = false;

    @Column(name = "description")
    private String description;

    @Column(name = "high_rsk_info")
    private boolean highRiskInfo;

    @Column(name = "ai_description")
    private String aiDescription;

    @Column(name = "ai_impact", columnDefinition = "text")
    private String aiImpact;

    @Column(name = "ai_category")
    private String aiCategory;

    @Column(name = "ai_before_code", columnDefinition = "text")
    private String aiBeforeCode;

    @Column(name = "ai_after_code", columnDefinition = "text")
    private String aiAfterCode;

    @Column(name = "ai_fix_steps", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> aiFixSteps;

    @Column(name = "ai_fix_complexity")
    private String aiFixComplexity;

    @Column(name = "ai_references", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> aiReferences;

    @Column(name = "ai_model")
    private String aiModel;

    @Column(name = "ai_confidence")
    private Double aiConfidence;

    @Column(name = "ai_analyzed_at")
    private LocalDateTime aiAnalyzedAt;

    @Column(name = "ai_raw_response", columnDefinition = "text")
    private String aiRawResponse;
}