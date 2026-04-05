import * as vscode from 'vscode';
import { Scanner } from './scanner';
import { Reporter } from './reporter';
import { AIAnalyzer } from './aiAnalyzer';
import { SecretAnalysisResult } from './types';

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
            
            const analyzer = new AIAnalyzer(apiKey);
            const secretApiResults = await analyzer.analyzeSecrets(secretFindings);

            const finalSecrets: SecretAnalysisResult[] = secretFindings.map((f, i) => ({
                ...f,
                aiAnalysis: secretApiResults[i] || { isFinding: true, severity: 'HIGH', explanation: 'Fallback analysis' }
            }));

            progress.report({ increment: 30, message: "Reading source files for Vulnerability Check..." });
            
            const files = await scanner.getWorkspaceFiles(progress);

            progress.report({ increment: 40, message: `Analyzing OWASP Vulns in ${files.length} files...` });

            const vulnResults = await analyzer.analyzeVulnerabilities(files, progress);
            
            progress.report({ increment: 100, message: "Done formatting results." });
            
            reporter.report(finalSecrets, vulnResults);

            const actualSecrets = finalSecrets.filter(r => r.aiAnalysis.isFinding);
            const totalIssues = actualSecrets.length + vulnResults.length;

            if (totalIssues > 0) {
                vscode.window.showWarningMessage(`Krypt found ${totalIssues} issue(s). Check Output channel for details.`);
            } else {
                vscode.window.showInformationMessage("No issues detected.");
            }
        });
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
