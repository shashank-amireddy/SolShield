#!/usr/bin/env node

import { Command } from 'commander';
import { GitHubRepositoryManager } from './core/RepositoryManager';
import { SecurityToolRunner } from './core/MultiToolRunner';
import { VulnerabilityReportAggregator } from './core/ReportAggregator';
import { ToolRegistry } from './core/ToolRegistry';
import { AnalysisDashboard } from './core/AnalysisDashboard';
import { VulnerabilityNormalizer } from './core/VulnerabilityNormalizer';
import { VulnerabilityDeduplicator } from './core/VulnerabilityDeduplicator';
import { CrossToolAnalyzer } from './core/CrossToolAnalyzer';
import { ConfigManager } from './utils/config';
import * as fs from 'fs-extra';
import * as path from 'path';
import chalk from 'chalk';

const program = new Command();

program
  .name('solidity-vulnerability-scanner')
  .description('Comprehensive security analysis platform for Solidity smart contracts')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan a GitHub repository or local directory for vulnerabilities')
  .argument('<path>', 'GitHub repository URL or local directory path to scan')
  .option('-o, --output <format>', 'Output format (json, html, markdown, dashboard)', 'json')
  .option('-f, --file <path>', 'Output file path')
  .option('--tools <tools>', 'Comma-separated list of tools to use (slither,mythril,smartcheck,solhint,securify2)')
  .option('--timeout <ms>', 'Timeout for each tool in milliseconds', '300000')
  .option('--token <token>', 'GitHub token for private repositories')
  .option('--verbose', 'Enable verbose logging')
  .action(async (githubUrl: string, options: any) => {
    try {
      await runScan(githubUrl, options);
    } catch (error) {
      console.error(chalk.red('Scan failed:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('list-tools')
  .description('List available security analysis tools')
  .action(async () => {
    const toolRegistry = ToolRegistry.getInstance();
    const toolNames = toolRegistry.getAvailableToolNames();
    
    console.log(chalk.blue('Available security analysis tools:'));
    for (const toolName of toolNames) {
      const tool = toolRegistry.createTool(toolName);
      if (tool) {
        const available = await tool.isAvailable();
        const status = available ? chalk.green('✓') : chalk.red('✗');
        console.log(`  ${status} ${tool.name} v${tool.version} - ${tool.description}`);
      }
    }
  });

async function runScan(pathOrUrl: string, options: any): Promise<void> {
  const startTime = Date.now();
  
  // Configure system
  const configManager = ConfigManager.getInstance();
  if (options.token) {
    configManager.setConfig({ githubToken: options.token });
  }
  if (options.timeout) {
    configManager.setConfig({ timeout: parseInt(options.timeout) });
  }

  // Initialize components
  const repositoryManager = new GitHubRepositoryManager();
  const toolRunner = new SecurityToolRunner();
  const reportAggregator = new VulnerabilityReportAggregator();
  const toolRegistry = ToolRegistry.getInstance();
  const dashboard = new AnalysisDashboard();

  console.log(chalk.blue('🔍 Starting Solidity vulnerability scan...'));
  console.log(chalk.gray(`Target: ${pathOrUrl}`));
  console.log(chalk.gray(`Output format: ${options.output}`));

  let repoPath: string;
  let isLocalPath = false;

  // Check if it's a local path or GitHub URL
  if (pathOrUrl.startsWith('http') || pathOrUrl.includes('github.com')) {
    // Step 1: Clone repository
    console.log(chalk.yellow('\n📥 Cloning repository...'));
    repoPath = await repositoryManager.cloneRepository(pathOrUrl);
  } else {
    // Local directory
    console.log(chalk.yellow('\n📁 Using local directory...'));
    repoPath = path.resolve(pathOrUrl);
    isLocalPath = true;
    
    if (!(await fs.pathExists(repoPath))) {
      console.log(chalk.red(`❌ Directory does not exist: ${repoPath}`));
      return;
    }
  }
  
  // Step 2: Discover Solidity files
  console.log(chalk.yellow('🔎 Discovering Solidity files...'));
  const solidityFiles = await repositoryManager.findSolidityFiles(repoPath);
  
  if (solidityFiles.length === 0) {
    console.log(chalk.red('❌ No Solidity files found in the repository'));
    await repositoryManager.cleanup(repoPath);
    return;
  }
  
  console.log(chalk.green(`✅ Found ${solidityFiles.length} Solidity files`));
  if (options.verbose) {
    solidityFiles.forEach(file => console.log(chalk.gray(`  - ${path.relative(repoPath, file)}`)));
  }

  // Step 3: Register and prepare tools
  console.log(chalk.yellow('\n🛠️  Preparing security analysis tools...'));
  
  let toolsToUse: string[];
  if (options.tools) {
    toolsToUse = options.tools.split(',').map((t: string) => t.trim().toLowerCase());
  } else {
    toolsToUse = toolRegistry.getAvailableToolNames();
  }

  const availableTools = [];
  for (const toolName of toolsToUse) {
    const tool = toolRegistry.createTool(toolName);
    if (tool && await tool.isAvailable()) {
      toolRunner.registerTool(tool);
      availableTools.push(tool);
      console.log(chalk.green(`✅ ${tool.name} v${tool.version} ready`));
    } else {
      console.log(chalk.red(`❌ ${toolName} not available`));
    }
  }

  if (availableTools.length === 0) {
    console.log(chalk.red('❌ No security analysis tools are available'));
    console.log(chalk.yellow('💡 To install tools:'));
    console.log(chalk.gray('   - Solhint: npm install -g solhint (✅ already installed)'));
    console.log(chalk.gray('   - Slither: pip install --user slither-analyzer'));
    console.log(chalk.gray('   - Mythril: pip install --user mythril (requires Visual C++ Build Tools)'));
    await repositoryManager.cleanup(repoPath);
    return;
  }

  // Step 4: Run security analysis
  console.log(chalk.yellow(`\n🔬 Running security analysis with ${availableTools.length} tools...`));
  const toolResults = await toolRunner.runAllTools(repoPath, {
    timeout: parseInt(options.timeout),
    additionalArgs: options.verbose ? ['--verbose'] : undefined
  });

  // Step 5: Process and aggregate results
  console.log(chalk.yellow('\n📊 Processing and aggregating results...'));
  
  const normalizer = new VulnerabilityNormalizer();
  const deduplicator = new VulnerabilityDeduplicator();
  const crossToolAnalyzer = new CrossToolAnalyzer();

  const normalizedVulnerabilities = normalizer.normalizeVulnerabilities(toolResults);
  const deduplicatedVulnerabilities = deduplicator.deduplicateVulnerabilities(normalizedVulnerabilities);
  const toolConsensus = crossToolAnalyzer.calculateToolConsensus(deduplicatedVulnerabilities, availableTools.map(t => t.name));
  const correlations = crossToolAnalyzer.analyzeCorrelations(deduplicatedVulnerabilities);

  // Step 6: Generate report
  console.log(chalk.yellow('\n📋 Generating report...'));
  
  const toolMetadata = toolResults.map(result => ({
    name: result.toolName,
    version: result.toolVersion,
    executionTime: result.executionTime,
    filesProcessed: solidityFiles.length
  }));

  const vulnerabilities = await reportAggregator.deduplicateFindings(toolResults);
  const report = await reportAggregator.generateReport(vulnerabilities, toolMetadata);
  
  // Update report metadata
  report.metadata.repositoryUrl = pathOrUrl;
  report.metadata.filesAnalyzed = solidityFiles.length;

  // Step 7: Output results
  const totalTime = Date.now() - startTime;
  console.log(chalk.green(`\n✅ Analysis complete in ${totalTime}ms`));
  
  // Print summary
  console.log(chalk.blue('\n📈 Summary:'));
  console.log(`  Total vulnerabilities: ${report.summary.totalVulnerabilities}`);
  console.log(`  Critical: ${chalk.red(report.summary.criticalCount)}`);
  console.log(`  High: ${chalk.yellow(report.summary.highCount)}`);
  console.log(`  Medium: ${chalk.blue(report.summary.mediumCount)}`);
  console.log(`  Low: ${chalk.green(report.summary.lowCount)}`);
  console.log(`  Tools used: ${report.summary.toolsUsed.join(', ')}`);

  // Generate output
  let outputContent: string;
  let fileExtension: string;

  if (options.output === 'dashboard') {
    const dashboardData = dashboard.generateDashboard(toolResults, toolMetadata, deduplicatedVulnerabilities, toolConsensus);
    outputContent = dashboard.formatDashboardHtml(dashboardData);
    fileExtension = 'html';
  } else {
    outputContent = reportAggregator.formatReport(report, options.output as 'json' | 'html' | 'markdown');
    fileExtension = options.output;
  }

  // Save to file if specified
  if (options.file) {
    await fs.writeFile(options.file, outputContent);
    console.log(chalk.green(`\n💾 Report saved to: ${options.file}`));
  } else {
    // Generate default filename
    const repoName = pathOrUrl.split('/').pop()?.replace('.git', '') || 'scan';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${repoName}-security-report-${timestamp}.${fileExtension}`;
    
    await fs.writeFile(filename, outputContent);
    console.log(chalk.green(`\n💾 Report saved to: ${filename}`));
  }

  // Print recommendations
  if (report.recommendations.length > 0) {
    console.log(chalk.blue('\n💡 Recommendations:'));
    report.recommendations.forEach((rec, index) => {
      console.log(`  ${index + 1}. ${rec}`);
    });
  }

  // Cleanup (only if we cloned a repository)
  if (!isLocalPath) {
    await repositoryManager.cleanup(repoPath);
  }
  
  // Exit with appropriate code
  const hasHighSeverity = report.summary.criticalCount > 0 || report.summary.highCount > 0;
  if (hasHighSeverity) {
    console.log(chalk.red('\n⚠️  High or critical vulnerabilities found. Review immediately before deployment.'));
    process.exit(1);
  } else {
    console.log(chalk.green('\n🎉 No critical or high severity vulnerabilities found.'));
    process.exit(0);
  }
}

// Handle uncaught errors
process.on('unhandledRejection', (reason, promise) => {
  console.error(chalk.red('Unhandled Rejection at:'), promise, chalk.red('reason:'), reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error(chalk.red('Uncaught Exception:'), error);
  process.exit(1);
});

program.parse();