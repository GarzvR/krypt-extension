export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface SecretFinding {
    filePath: string;
    lineNumber: number;
    matchedText: string;
    context: string;
}

export interface WorkspaceFile {
    filePath: string;
    content: string;
}

export interface AIFindingResult {
    isFinding: boolean;
    severity?: Severity;
    explanation?: string;
    lineNumber?: number;
}

export interface SecretAnalysisResult extends SecretFinding {
    aiAnalysis: AIFindingResult;
}

export interface VulnAnalysisResult {
    filePath: string;
    lineNumber: number;
    severity: Severity;
    explanation: string;
}
