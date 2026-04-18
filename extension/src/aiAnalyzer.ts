import * as https from 'https';
import { SecretFinding, AIFindingResult, WorkspaceFile, VulnAnalysisResult, SecretAnalysisResult } from './types';

export class AIAnalyzer {
    private apiKey: string;
    private readonly apiUrl = 'https://openrouter.ai/api/v1/chat/completions';
    private scannerModel: string;
    private verifierModel: string;
    private escalationModel: string;

    constructor(apiKey: string, scannerModel: string, verifierModel: string, escalationModel: string) {
        this.apiKey = apiKey;
        this.scannerModel = scannerModel;
        this.verifierModel = verifierModel;
        this.escalationModel = escalationModel;
    }

    private readonly KNOWN_SAFE_FILES = [
        'firebase.js', 'firebase.ts', 'firebaseConfig.js', 'firebaseConfig.ts',
        'firebase-config.js', 'firebase-config.ts', 'firebaseAdmin.js'
    ];

    private readonly KNOWN_SAFE_PATTERNS = [
        'firebaseConfig', 'initializeApp', 'apiKey', 'authDomain',
        'storageBucket', 'messagingSenderId', 'appId', 'measurementId',
        'projectId', 'databaseURL'
    ];

    private isKnownSafePattern(filePath: string, text?: string): boolean {
        const fileName = filePath.split('/').pop() || '';
        if (this.KNOWN_SAFE_FILES.some(f => fileName === f)) return true;
        if (text && this.KNOWN_SAFE_PATTERNS.some(p => text.includes(p))) return true;
        return false;
    }

    private readonly SYSTEM_PROMPT = `You are a professional static security analysis AI.
Your ONLY goal is to produce HIGH-ACCURACY findings with MINIMAL false positives.
You must think like a real security engineer, not a pattern-matching bot.

CORE RULES:
1. NEVER flag something as a vulnerability without a realistic exploit scenario.
2. Exposure does NOT equal Vulnerability. Public or visible code/config is NOT automatically a security issue.
3. Context is mandatory: You MUST analyze: Is the code reachable? Is it actually used? Is there protection (auth, rules, validation)?
4. If risk depends on configuration, mark as "Potential Risk", NOT CRITICAL.
5. If unsure, lower severity + lower confidence.

CRITICAL THINKING CHECK (MANDATORY):
Before marking any finding, ask:
- Can an attacker actually abuse this?
- What exact step would they take?
- What do they gain?
If you cannot clearly answer these, DO NOT mark as HIGH/CRITICAL.

SEVERITY SYSTEM:
- LOW: Code quality issues, minor privacy risks, misleading behavior.
- MEDIUM: Conditional risks depending on configuration or misuse.
- HIGH: Real vulnerability with clear attack path and meaningful impact.
- CRITICAL: Direct exploitation possible immediately (no special conditions).

FIREBASE RULE (STRICT):
Firebase API keys in frontend are PUBLIC and EXPECTED. DO NOT flag Firebase config as CRITICAL.
ONLY flag if: Security rules allow public read/write OR clear abuse scenario exists.
Otherwise: classify as LOW/MEDIUM, Issue Type: "Potential Misconfiguration Risk".

API KEY LOGIC:
- Server-side secret exposed: HIGH/CRITICAL.
- Client-side key: NOT a vulnerability unless it grants real access.
- In-memory storage: NOT a vulnerability by itself. ONLY if exposed/logged/leaked.

BACKEND ANALYSIS:
1. Missing rate limiting: MEDIUM (HIGH if easily abused).
2. Missing authentication/authorization: HIGH/CRITICAL depending on access.
3. Sensitive data storage: Plaintext file LOW/MEDIUM. Public exposure: escalate.
4. Injection risks (SQL, command, eval): HIGH/CRITICAL.

ERROR HANDLING:
- Empty catch: LOW. Misleading data: LOW. Security failure ignored: MEDIUM.

FALSE POSITIVE CONTROL:
- Prefer UNDER-reporting over OVER-reporting.
- Do NOT assume worst-case without evidence.
- Use Confidence: Low/Medium/High.

FINAL RULE:
If the issue requires unlikely conditions, depends on external configuration, or is expected framework behavior: DO NOT mark as CRITICAL.

Your identity: A calm, precise, no-drama security engineer. NOT a paranoid vulnerability generator.`;

    public async analyzeSecrets(findings: SecretFinding[]): Promise<AIFindingResult[]> {
        if (findings.length === 0) return [];

        let prompt = `Analyze each code snippet to determine if it is a real EXPOSED SECRET.\n`;
        prompt += `For each finding you MUST: explain WHY it is a problem, explain HOW it could be exploited, mention IF it depends on configuration, and state your Confidence level (Low/Medium/High).\n`;
        prompt += `Respond strictly with a JSON object containing an "analysis" array. Each item must have this structure:\n`;
        prompt += `{ "isFinding": boolean, "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", "explanation": "Brief english explanation including confidence level" }\n\n`;
        
        findings.forEach((finding, index) => {
            prompt += `--- Snippet ${index} ---\n`;
            prompt += `File: ${finding.filePath}:${finding.lineNumber}\n`;
            prompt += `Context:\n${finding.context}\n\n`;
        });

        const requestData = JSON.stringify({
            model: this.scannerModel,
            max_tokens: 1500,
            messages: [
                {
                    role: 'system',
                    content: this.SYSTEM_PROMPT + '\nRespond ONLY with a valid JSON object.'
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

    private async executePass2(prompt: string): Promise<{status: string, explanation: string}> {
        const pass2System = `You are a strict second-pass security reviewer. Your job is to review findings from Pass 1 and remove FALSE POSITIVES.

Before evaluating each finding, apply the CRITICAL THINKING CHECK:
- Can an attacker actually abuse this?
- What exact step would they take?
- What do they gain?
If you cannot clearly answer these: mark as FALSE_POSITIVE.

RULES:
1. Only keep findings that are DEFINITELY real security issues with realistic exploit scenarios.
2. Exposure does NOT equal Vulnerability. Public config is NOT automatically a security issue.
3. Firebase API keys are PUBLIC by design. Do NOT confirm as CRITICAL. At most MEDIUM if security rules are unknown.
4. Server-side secrets exposed: confirm as HIGH/CRITICAL. Client-side keys: only confirm if they grant real access.
5. In-memory storage alone is NOT a vulnerability.
6. Missing rate limiting: MEDIUM or HIGH depending on abuse impact.
7. Plaintext data storage: LOW or MEDIUM depending on accessibility.
8. Empty catch blocks: LOW. Security-relevant failures ignored: MEDIUM.
9. Include Confidence (Low/Medium/High) in the explanation.
10. Prefer UNDER-reporting. If unsure, mark as UNCERTAIN.
11. Respond with a JSON object containing "status" (CONFIRMED, FALSE_POSITIVE, or UNCERTAIN) and "explanation".`;

        const reqData = JSON.stringify({
            model: this.verifierModel,
            max_tokens: 600,
            messages: [
                { role: 'system', content: pass2System },
                { role: 'user', content: prompt }
            ],
            response_format: { type: 'json_object' }
        });
        
        try {
            const raw = await this.makeRequest(reqData);
            const parsed = JSON.parse(raw);
            const content = parsed.choices?.[0]?.message?.content || "";
            const clean = content.replace(/```json/g, '').replace(/```/g, '').trim();
            const result = JSON.parse(clean);
            return { status: result.status || 'UNCERTAIN', explanation: result.explanation || '' };
        } catch (e) {
            return { status: 'UNCERTAIN', explanation: 'Failed Pass 2' };
        }
    }

    private async executePass3(prompt: string): Promise<{status: string, explanation: string}> {
        const pass3System = `You are a final-verdict security judge using deep reasoning. This is an ESCALATION from Pass 2 where the reviewer was uncertain.
You MUST make a binary decision: CONFIRMED or FALSE_POSITIVE. No middle ground.

CRITICAL THINKING CHECK (MANDATORY):
Before deciding, you MUST answer:
- Can an attacker actually abuse this?
- What exact step would they take?
- What do they gain?
If you cannot clearly answer all three: FALSE_POSITIVE.

RULES:
1. Analyze the finding with full technical reasoning.
2. Firebase API keys in frontend are PUBLIC and EXPECTED. Do NOT confirm unless security rules are provably weak.
3. Server-side secrets: confirm if exposed. Client-side keys: only confirm if they grant real access.
4. Only CONFIRM if there is a realistic, exploitable attack scenario with clear impact.
5. If the issue requires unlikely conditions, depends on external configuration, or is expected framework behavior: FALSE_POSITIVE.
6. Explain your technical reasoning clearly.
7. Respond ONLY with a valid JSON containing "status" (CONFIRMED or FALSE_POSITIVE) and "explanation".`;

        const reqData = JSON.stringify({
            model: this.escalationModel,
            max_tokens: 600,
            messages: [
                { role: 'system', content: pass3System },
                { role: 'user', content: prompt }
            ],
            response_format: { type: 'json_object' }
        });
        
        try {
            const raw = await this.makeRequest(reqData);
            const parsed = JSON.parse(raw);
            const content = parsed.choices?.[0]?.message?.content || "";
            const clean = content.replace(/```json/g, '').replace(/```/g, '').trim();
            const result = JSON.parse(clean);
            return { status: result.status === 'CONFIRMED' ? 'CONFIRMED' : 'FALSE_POSITIVE', explanation: result.explanation || 'R1 Verdict' };
        } catch (e) {
            return { status: 'CONFIRMED', explanation: 'Pass 3 Failed, defaulting to CONFIRMED' };
        }
    }

    public async verifySecretsPass2(secrets: SecretAnalysisResult[]): Promise<{verified: SecretAnalysisResult[], uncertain: SecretAnalysisResult[], filtered: number}> {
        const verified: SecretAnalysisResult[] = [];
        const uncertain: SecretAnalysisResult[] = [];
        let filtered = 0;
        
        for (const secret of secrets) {
            if (this.isKnownSafePattern(secret.filePath, secret.matchedText || secret.context)) {
                filtered++;
                continue;
            }
            let prompt = `--- FINDING TO VERIFY ---
File: ${secret.filePath}:${secret.lineNumber}
Trigger Regex Match: ${secret.matchedText}
Scanner Note: ${secret.aiAnalysis.explanation}
Code Context:
${secret.context}
`;
            const { status, explanation } = await this.executePass2(prompt);
            
            if (status === 'CONFIRMED') {
                secret.aiAnalysis.explanation = `[Pass 2 Confirmed] ${explanation}`;
                verified.push(secret);
            } else if (status === 'FALSE_POSITIVE') {
                filtered++;
            } else {
                secret.aiAnalysis.explanation = `[Pass 2 Uncertain] ${explanation}`;
                uncertain.push(secret);
            }
        }
        return { verified, uncertain, filtered };
    }

    public async escalateSecretsPass3(secrets: SecretAnalysisResult[]): Promise<{verified: SecretAnalysisResult[], filtered: number}> {
        const verified: SecretAnalysisResult[] = [];
        let filtered = 0;
        for (const secret of secrets) {
            let prompt = `--- ESCALATED FINDING ---
File: ${secret.filePath}:${secret.lineNumber}
Trigger Regex Match: ${secret.matchedText}
Pass 2 Auditor Note: ${secret.aiAnalysis.explanation}
Code Context:
${secret.context}
`;
            const { status, explanation } = await this.executePass3(prompt);
            
            if (status === 'CONFIRMED') {
                secret.aiAnalysis.explanation = `[Pass 3 R1 Confirmed] ${explanation}`;
                verified.push(secret);
            } else {
                filtered++;
            }
        }
        return { verified, filtered };
    }

    public async verifyVulnerabilitiesPass2(vulns: VulnAnalysisResult[]): Promise<{verified: VulnAnalysisResult[], uncertain: VulnAnalysisResult[], filtered: number}> {
        const verified: VulnAnalysisResult[] = [];
        const uncertain: VulnAnalysisResult[] = [];
        let filtered = 0;
        
        for (const vuln of vulns) {
            if (this.isKnownSafePattern(vuln.filePath, vuln.explanation)) {
                filtered++;
                continue;
            }
            let prompt = `--- FINDING TO VERIFY ---
File: ${vuln.filePath}:${vuln.lineNumber}
Reported Severity: ${vuln.severity}
Scanner Explanation: ${vuln.explanation}
`;
            const { status, explanation } = await this.executePass2(prompt);
            
            if (status === 'CONFIRMED') {
                vuln.explanation = `[Pass 2 Confirmed] ${explanation}`;
                verified.push(vuln);
            } else if (status === 'FALSE_POSITIVE') {
                filtered++;
            } else {
                vuln.explanation = `[Pass 2 Uncertain] ${explanation}`;
                uncertain.push(vuln);
            }
        }
        return { verified, uncertain, filtered };
    }

    public async escalateVulnerabilitiesPass3(vulns: VulnAnalysisResult[]): Promise<{verified: VulnAnalysisResult[], filtered: number}> {
        const verified: VulnAnalysisResult[] = [];
        let filtered = 0;
        for (const vuln of vulns) {
            let prompt = `--- ESCALATED FINDING ---
File: ${vuln.filePath}:${vuln.lineNumber}
Reported Severity: ${vuln.severity}
Pass 2 Auditor Note: ${vuln.explanation}
`;
            const { status, explanation } = await this.executePass3(prompt);
            
            if (status === 'CONFIRMED') {
                vuln.explanation = `[Pass 3 R1 Confirmed] ${explanation}`;
                verified.push(vuln);
            } else {
                filtered++;
            }
        }
        return { verified, filtered };
    }

    private async analyzeSingleFile(file: WorkspaceFile): Promise<VulnAnalysisResult[]> {
        let prompt = `Analyze the following source code file for security vulnerabilities.\n\n`;
        prompt += `CRITICAL THINKING CHECK (MANDATORY):\n`;
        prompt += `Before reporting any finding, you MUST answer:\n`;
        prompt += `- Can an attacker actually abuse this?\n`;
        prompt += `- What exact step would they take?\n`;
        prompt += `- What do they gain?\n`;
        prompt += `If you cannot clearly answer these, DO NOT report the finding.\n\n`;
        prompt += `For each finding you MUST provide:\n`;
        prompt += `1. Issue Type: Misconfiguration Risk, Bad Practice, or Actual Exploitable Vulnerability.\n`;
        prompt += `2. Why it matters: Technical reasoning.\n`;
        prompt += `3. Exploit Scenario: How it could be exploited.\n`;
        prompt += `4. Conditions Required: What must be true for exploitation.\n`;
        prompt += `5. Suggested Fix.\n`;
        prompt += `6. Confidence: Low, Medium, or High.\n\n`;
        prompt += `CHECKS TO PERFORM:\n`;
        prompt += `- Injection risks (SQL, command, XSS, eval)\n`;
        prompt += `- Missing authentication/authorization\n`;
        prompt += `- Missing rate limiting (MEDIUM or HIGH if easily abused)\n`;
        prompt += `- Sensitive data storage (plaintext file: LOW/MEDIUM, public: escalate)\n`;
        prompt += `- Improper error handling (empty catch: LOW, security failure ignored: MEDIUM)\n`;
        prompt += `- Sensitive data exposure\n\n`;
        prompt += `Respond strictly with a JSON object containing an "issues" array.\n`;
        prompt += `Each item must have this structure:\n`;
        prompt += `{ "lineNumber": number, "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", "explanation": "Brief english explanation" }\n`;
        prompt += `ATTENTION: Fewer but accurate findings is better than many incorrect ones. If none, return { "issues": [] }.\n\n`;
        prompt += `--- FILE: ${file.filePath} ---\n`;
        prompt += `${file.content}\n`;

        const requestData = JSON.stringify({
            model: this.scannerModel,
            max_tokens: 2000,
            messages: [
                {
                    role: 'system',
                    content: this.SYSTEM_PROMPT + '\nRespond ONLY with a valid JSON object.'
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
