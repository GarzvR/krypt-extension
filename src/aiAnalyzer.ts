import * as https from 'https';
import { SecretFinding, AIFindingResult, WorkspaceFile, VulnAnalysisResult } from './types';

export class AIAnalyzer {
    private apiKey: string;
    private readonly apiUrl = 'https://openrouter.ai/api/v1/chat/completions';
    private readonly model = 'deepseek/deepseek-v3.2';

    constructor(apiKey: string) {
        this.apiKey = apiKey;
    }

    public async analyzeSecrets(findings: SecretFinding[]): Promise<AIFindingResult[]> {
        if (findings.length === 0) return [];

        let prompt = `Analyze each code snippet to determine if it is a real EXPOSED SECRET.\n`;
        prompt += `Respond strictly with a JSON object containing an "analysis" array. Each item must have this structure:\n`;
        prompt += `{ "isFinding": boolean, "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", "explanation": "Brief english explanation" }\n\n`;
        
        findings.forEach((finding, index) => {
            prompt += `--- Snippet ${index} ---\n`;
            prompt += `File: ${finding.filePath}:${finding.lineNumber}\n`;
            prompt += `Context:\n${finding.context}\n\n`;
        });

        const requestData = JSON.stringify({
            model: this.model,
            max_tokens: 1500,
            messages: [
                {
                    role: 'system',
                    content: 'You are a security expert. Respond ONLY with a valid JSON array of objects.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            response_format: { type: 'json_object' }
        });

        try {
            const resultRaw = await this.makeRequest(requestData);
            return this.parseSecretResult(resultRaw, findings.length);
        } catch (error: any) {
            return findings.map(() => ({
                isFinding: true,
                severity: 'HIGH',
                explanation: `API Error: ${error.message}`
            }));
        }
    }

    public async analyzeVulnerabilities(
        files: WorkspaceFile[],
        progress?: any
    ): Promise<VulnAnalysisResult[]> {
        let allVulns: VulnAnalysisResult[] = [];
        
        for (let i = 0; i < files.length; i += 3) {
            if (progress) {
                progress.report({ message: `Analyzing OWASP Vulns (Batch ${Math.floor(i/3) + 1} of ${Math.ceil(files.length/3)})...` });
            }
            const batch = files.slice(i, i + 3);
            const promises = batch.map(file => this.analyzeSingleFile(file));
            const results = await Promise.all(promises);
            results.forEach(res => {
                allVulns = allVulns.concat(res);
            });
        }

        return allVulns;
    }

    private async analyzeSingleFile(file: WorkspaceFile): Promise<VulnAnalysisResult[]> {
        let prompt = `Analyze the following complete source code file for OWASP Top 10 vulnerabilities (SQL injection, XSS, Broken Auth, Insecure Deserialization, Security Misconfig, Sensitive Data Exposure, Missing Access Control).\n\n`;
        prompt += `Respond strictly with a JSON object containing an "issues" array.\n`;
        prompt += `Each item must have this structure:\n`;
        prompt += `{ "lineNumber": number, "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", "explanation": "Brief english explanation" }\n`;
        prompt += `ATTENTION: Only report genuine, high-confidence vulnerabilities. If none, return { "issues": [] }.\n\n`;
        prompt += `--- FILE: ${file.filePath} ---\n`;
        prompt += `${file.content}\n`;

        const requestData = JSON.stringify({
            model: this.model,
            max_tokens: 2000,
            messages: [
                {
                    role: 'system',
                    content: 'You are a strict security expert code reviewer. Respond ONLY with a valid JSON array of objects.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            response_format: { type: 'json_object' } 
        });

        try {
            const resultRaw = await this.makeRequest(requestData);
            return this.parseVulnResult(resultRaw, file.filePath);
        } catch (error: any) {
            return [{
                filePath: file.filePath,
                lineNumber: 1,
                severity: 'MEDIUM',
                explanation: `API Error analyzing file: ${error.message}`
            }];
        }
    }

    private makeRequest(data: string): Promise<string> {
        return new Promise((resolve, reject) => {
            const url = new URL(this.apiUrl);
            const options = {
                hostname: url.hostname,
                path: url.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`,
                    'HTTP-Referer': 'https://krypt.extension',
                    'X-Title': 'Krypt VSCode Extension', 
                }
            };

            const req = https.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => body += chunk);
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(body);
                    } else {
                        reject(new Error(`Status ${res.statusCode}: ${body}`));
                    }
                });
            });

            req.on('error', (e) => reject(e));
            req.write(data);
            req.end();
        });
    }

    private parseSecretResult(rawResponse: string, expectedCount: number): AIFindingResult[] {
        try {
            const parsed = JSON.parse(rawResponse);
            const content = parsed.choices?.[0]?.message?.content;
            if (!content) throw new Error("No content");

            const cleanContent = content.replace(/```json/g, '').replace(/```/g, '').trim();
            const resultList = JSON.parse(cleanContent);
            
            if (resultList && Array.isArray(resultList.analysis)) {
                return resultList.analysis;
            } else if (Array.isArray(resultList)) {
                return resultList;
            }
            
            throw new Error("Invalid output format");
            
        } catch (e) {
            return Array(expectedCount).fill({
                isFinding: true,
                severity: 'HIGH',
                explanation: 'Parsing failed.'
            });
        }
    }

    private parseVulnResult(rawResponse: string, filePath: string): VulnAnalysisResult[] {
        try {
            const parsed = JSON.parse(rawResponse);
            const content = parsed.choices?.[0]?.message?.content;
            if (!content) throw new Error("No content");

            const cleanContent = content.replace(/```json/g, '').replace(/```/g, '').trim();
            const resultList = JSON.parse(cleanContent);
            
            let issues: any[] = [];
            if (resultList && Array.isArray(resultList.issues)) {
                issues = resultList.issues;
            } else if (Array.isArray(resultList)) {
                issues = resultList;
            }
            
            return issues.map(issue => ({
                filePath: filePath,
                lineNumber: issue.lineNumber || 1,
                severity: issue.severity || 'MEDIUM',
                explanation: issue.explanation || 'Unknown issue'
            }));
            
        } catch (e) {
            return [];
        }
    }
}
