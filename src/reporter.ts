import * as vscode from 'vscode';
import { SecretAnalysisResult, VulnAnalysisResult } from './types';

export class Reporter {
    private channel: vscode.OutputChannel;

    constructor() {
        this.channel = vscode.window.createOutputChannel('Krypt Security');
    }

    public report(secrets: SecretAnalysisResult[], vulns: VulnAnalysisResult[]) {
        this.channel.clear();
        this.channel.show();

        const actualSecrets = secrets.filter(r => r.aiAnalysis.isFinding);

        if (actualSecrets.length === 0 && vulns.length === 0) {
            this.channel.appendLine('No issues detected in the workspace.');
            return;
        }

        this.channel.appendLine(`Krypt Security Scan Results\n`);

        this.channel.appendLine(`--- SECRETS FOUND (${actualSecrets.length}) ---`);
        this.printSecrets(actualSecrets);

        this.channel.appendLine(`\n--- VULNERABILITIES FOUND (${vulns.length}) ---`);
        this.printVulns(vulns);
    }

    private printSecrets(items: SecretAnalysisResult[]) {
        if (items.length === 0) {
            this.channel.appendLine('None found.');
            return;
        }

        const sorted = items.sort((a, b) => {
            const getRank = (sev?: string) => {
                switch(sev) {
                    case 'CRITICAL': return 0;
                    case 'HIGH': return 1;
                    case 'MEDIUM': return 2;
                    case 'LOW': return 3;
                    default: return 4;
                }
            };
            return getRank(a.aiAnalysis.severity) - getRank(b.aiAnalysis.severity);
        });

        for (const item of sorted) {
            const severity = item.aiAnalysis.severity || 'UNKNOWN';
            this.channel.appendLine(`[${severity}] ${item.filePath}:${item.lineNumber}`);
            this.channel.appendLine(`Explanation: ${item.aiAnalysis.explanation}`);
            this.channel.appendLine('----------------------------------------------------');
        }
    }

    private printVulns(items: VulnAnalysisResult[]) {
        if (items.length === 0) {
            this.channel.appendLine('None found.');
            return;
        }

        const sorted = items.sort((a, b) => {
            const getRank = (sev?: string) => {
                switch(sev) {
                    case 'CRITICAL': return 0;
                    case 'HIGH': return 1;
                    case 'MEDIUM': return 2;
                    case 'LOW': return 3;
                    default: return 4;
                }
            };
            return getRank(a.severity) - getRank(b.severity);
        });

        for (const item of sorted) {
            this.channel.appendLine(`[${item.severity}] ${item.filePath}:${item.lineNumber}`);
            this.channel.appendLine(`Explanation: ${item.explanation}`);
            this.channel.appendLine('----------------------------------------------------');
        }
    }
}
