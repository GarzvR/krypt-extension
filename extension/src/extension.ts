import * as vscode from 'vscode';
import { Scanner } from './scanner';
import { Reporter } from './reporter';
import { AIAnalyzer } from './aiAnalyzer';
import { SecretAnalysisResult, VulnAnalysisResult } from './types';

export function activate(context: vscode.ExtensionContext) {
    const reporter = new Reporter();

    const disposable = vscode.commands.registerCommand('krypt.scanForSecrets', async () => {
        const config = vscode.workspace.getConfiguration('krypt');
        const apiKey = config.get<string>('openRouterApiKey');

        if (!apiKey) {
            const action = await vscode.window.showWarningMessage(
                'Krypt needs an OpenRouter API key to analyze code. Please set krypt.openRouterApiKey in your Settings.',
                'Open Settings'
            );
            if (action === 'Open Settings') {
                vscode.commands.executeCommand('workbench.action.openSettings', 'krypt.openRouterApiKey');
            }
            return;
        }

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Krypt Security",
            cancellable: false
        }, async (progress) => {
            progress.report({ increment: 0, message: "Scanning for secrets..." });
            
            const scanner = new Scanner();
            const secretFindings = await scanner.scanWorkspaceForSecrets(progress, 20);

            progress.report({ increment: 20, message: `Analyzing ${secretFindings.length} secret candidates...` });
            
            const scannerModel = config.get<string>('scannerModel') || 'deepseek/deepseek-v3.2';
            const verifierModel = config.get<string>('verifierModel') || 'deepseek/deepseek-v3.2';
            const escalationModel = config.get<string>('escalationModel') || 'deepseek/deepseek-r1';

            const analyzer = new AIAnalyzer(apiKey, scannerModel, verifierModel, escalationModel);
            const secretApiResults = await analyzer.analyzeSecrets(secretFindings);

            const finalSecrets: SecretAnalysisResult[] = secretFindings.map((f, i) => ({
                ...f,
                aiAnalysis: secretApiResults[i] || { isFinding: true, severity: 'HIGH', explanation: 'Fallback analysis' }
            }));

            progress.report({ increment: 30, message: "Reading source files for Vulnerability Check..." });
            
            const files = await scanner.getWorkspaceFiles(progress);

            progress.report({ increment: 40, message: `Analyzing OWASP Vulns in ${files.length} files...` });

            let vulnResults = await analyzer.analyzeVulnerabilities(files, progress);
            
            progress.report({ increment: 70, message: "Pass 2: Verifying findings..." });
            
            const actualSecrets = finalSecrets.filter(r => r.aiAnalysis.isFinding);
            
            let verifiedSecrets = actualSecrets;
            let filteredCount = 0;
            let pass3Used = false;
            let uncertainSecrets: SecretAnalysisResult[] = [];
            let uncertainVulns: VulnAnalysisResult[] = [];

            if (actualSecrets.length > 0) {
                const sRes = await analyzer.verifySecretsPass2(actualSecrets);
                verifiedSecrets = sRes.verified;
                uncertainSecrets = sRes.uncertain;
                filteredCount += sRes.filtered;
            }
            
            if (vulnResults.length > 0) {
                const vRes = await analyzer.verifyVulnerabilitiesPass2(vulnResults);
                vulnResults = vRes.verified;
                uncertainVulns = vRes.uncertain;
                filteredCount += vRes.filtered;
            }

            if (uncertainSecrets.length > 0 || uncertainVulns.length > 0) {
                pass3Used = true;
                progress.report({ increment: 85, message: "Pass 3: Escalating uncertain findings..." });
                
                if (uncertainSecrets.length > 0) {
                    const escS = await analyzer.escalateSecretsPass3(uncertainSecrets);
                    verifiedSecrets.push(...escS.verified);
                    filteredCount += escS.filtered;
                }
                
                if (uncertainVulns.length > 0) {
                    const escV = await analyzer.escalateVulnerabilitiesPass3(uncertainVulns);
                    vulnResults.push(...escV.verified);
                    filteredCount += escV.filtered;
                }
            }

            progress.report({ increment: 100, message: "Done formatting results." });
            
            const passMsg = filteredCount > 0 ? `${filteredCount} findings filtered as false positives across ${pass3Used ? '3' : '2'} passes.` : undefined;
            reporter.report(verifiedSecrets, vulnResults, passMsg);

            const totalIssues = verifiedSecrets.length + vulnResults.length;

            if (totalIssues > 0) {
                vscode.window.showWarningMessage(`Krypt found ${totalIssues} verified issue(s). Check Output channel for details.`);
            } else {
                vscode.window.showInformationMessage("No issues detected after multi-pass verification.");
            }
        });
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
