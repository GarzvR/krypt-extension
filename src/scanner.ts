import * as vscode from 'vscode';
import { SecretFinding, WorkspaceFile } from './types';

export class Scanner {
    private readonly secretPatterns = [
        /(?:api_key|apikey|secret|password|token)[^\w]{1,5}['"]?([a-zA-Z0-9_\-]{16,})['"]?/gi,
        /['"]?(?:sk-[a-zA-Z0-9]{20,})['"]?/g,
        /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi,
    ];

    public async scanWorkspaceForSecrets(
        progress: vscode.Progress<{ message?: string; increment?: number }>,
        progressRatio: number
    ): Promise<SecretFinding[]> {
        const findings: SecretFinding[] = [];
        const files = await vscode.workspace.findFiles(
            '**/*.{ts,js,tsx,jsx,py,go,java,php,rb}',
            '**/{node_modules,.git,.vscode,dist,out,.next,build,.env,.env.local,.env.example,.env.production}/**'
        );

        let scannedCount = 0;

        for (const fileUrl of files) {
            try {
                scannedCount++;
                if (scannedCount % 5 === 0) {
                    progress.report({ increment: (5 / files.length) * progressRatio });
                }

                const fileData = await vscode.workspace.fs.readFile(fileUrl);
                const fileContent = Buffer.from(fileData).toString('utf8');
                const lines = fileContent.split(/\r?\n/);

                for (let i = 0; i < lines.length; i++) {
                    const line = lines[i];

                    for (const regex of this.secretPatterns) {
                        regex.lastIndex = 0;
                        let match = regex.exec(line);
                        while (match !== null) {
                            const contextStart = Math.max(0, i - 1);
                            const contextEnd = Math.min(lines.length - 1, i + 1);
                            const contextLines = lines.slice(contextStart, contextEnd + 1).join('\n');

                            findings.push({
                                filePath: vscode.workspace.asRelativePath(fileUrl),
                                lineNumber: i + 1,
                                matchedText: match[0],
                                context: contextLines
                            });
                            match = regex.exec(line);
                        }
                    }
                }
            } catch (err) {
            }
        }

        return findings;
    }

    public async getWorkspaceFiles(
        progress: vscode.Progress<{ message?: string; increment?: number }>
    ): Promise<WorkspaceFile[]> {
        const foundFiles: WorkspaceFile[] = [];
        const files = await vscode.workspace.findFiles(
            '**/*.{ts,js,tsx,jsx,py,go,java,php,rb}',
            '**/{node_modules,.git,.vscode,dist,out,.next,build,.env,.env.local,.env.example,.env.production,tests,test,__tests__}/**'
        );

        for (const fileUrl of files) {
            try {
                const stat = await vscode.workspace.fs.stat(fileUrl);
                if (stat.size > 200000) {
                    continue; 
                }

                const fileData = await vscode.workspace.fs.readFile(fileUrl);
                const fileContent = Buffer.from(fileData).toString('utf8');
                
                foundFiles.push({
                    filePath: vscode.workspace.asRelativePath(fileUrl),
                    content: fileContent
                });
            } catch (err) {
            }
        }

        return foundFiles;
    }
}
