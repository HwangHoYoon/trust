package com.fast.trust.scan.dto;

import lombok.Data;

import java.util.List;

@Data
public class SSEDto {
    private String scanId;
    private String scanDetailId;
    private String type;
    private String name;
    private String percent;
    private String severity;
    private Integer score;
    private String grade;
    private String description;
    private boolean aiAnalyzed;
    private String aiDescription;
    private String aiAfterCode;
    private String aiBeforeCode;
    private String aiImpact;
    private List<String> aiFixSteps;
    private List<String> aiReferences;
}
