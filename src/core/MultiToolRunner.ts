import { MultiToolRunner, SecurityTool, ToolResult, ToolOptions } from '../types';
import { ConfigManager } from '../utils/config';

export class SecurityToolRunner implements MultiToolRunner {
  private tools: Map<string, SecurityTool> = new Map();
  private configManager: ConfigManager;

  constructor() {
    this.configManager = ConfigManager.getInstance();
  }

  registerTool(tool: SecurityTool): void {
    if (!tool.name || !tool.version) {
      throw new Error('Tool must have a name and version');
    }

    if (this.tools.has(tool.name)) {
      console.warn(`Tool ${tool.name} is already registered. Overwriting with new version.`);
    }

    this.tools.set(tool.name, tool);
    console.log(`Registered security tool: ${tool.name} v${tool.version}`);
  }

  async runAllTools(repoPath: string, options?: ToolOptions): Promise<ToolResult[]> {
    const availableTools = Array.from(this.tools.values());
    
    if (availableTools.length === 0) {
      console.warn('No security tools registered');
      return [];
    }

    console.log(`Running ${availableTools.length} security tools on repository: ${repoPath}`);
    
    // Check tool availability first
    const enabledTools: SecurityTool[] = [];
    for (const tool of availableTools) {
      try {
        if (await tool.isAvailable()) {
          enabledTools.push(tool);
        } else {
          console.warn(`Tool ${tool.name} is not available, skipping`);
        }
      } catch (error) {
        console.warn(`Failed to check availability of tool ${tool.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    if (enabledTools.length === 0) {
      console.warn('No security tools are available');
      return [];
    }

    // Run tools in parallel with error isolation
    const toolPromises = enabledTools.map(tool => this.runToolSafely(tool, repoPath, options));
    const results = await Promise.allSettled(toolPromises);

    const successfulResults: ToolResult[] = [];
    const failedTools: string[] = [];

    results.forEach((result, index) => {
      const toolName = enabledTools[index].name;
      if (result.status === 'fulfilled') {
        successfulResults.push(result.value);
        console.log(`Tool ${toolName} completed successfully`);
      } else {
        failedTools.push(toolName);
        console.error(`Tool ${toolName} failed: ${result.reason}`);
      }
    });

    if (failedTools.length > 0) {
      console.warn(`${failedTools.length} tools failed: ${failedTools.join(', ')}`);
    }

    console.log(`Analysis complete. ${successfulResults.length} tools succeeded, ${failedTools.length} failed.`);
    return successfulResults;
  }

  async runSpecificTools(repoPath: string, toolNames: string[], options?: ToolOptions): Promise<ToolResult[]> {
    if (toolNames.length === 0) {
      return [];
    }

    const requestedTools: SecurityTool[] = [];
    const missingTools: string[] = [];

    for (const toolName of toolNames) {
      const tool = this.tools.get(toolName);
      if (tool) {
        requestedTools.push(tool);
      } else {
        missingTools.push(toolName);
      }
    }

    if (missingTools.length > 0) {
      console.warn(`Requested tools not found: ${missingTools.join(', ')}`);
    }

    if (requestedTools.length === 0) {
      throw new Error(`None of the requested tools are available: ${toolNames.join(', ')}`);
    }

    console.log(`Running ${requestedTools.length} specific tools: ${requestedTools.map(t => t.name).join(', ')}`);

    // Check availability and run tools
    const enabledTools: SecurityTool[] = [];
    for (const tool of requestedTools) {
      try {
        if (await tool.isAvailable()) {
          enabledTools.push(tool);
        } else {
          console.warn(`Requested tool ${tool.name} is not available`);
        }
      } catch (error) {
        console.warn(`Failed to check availability of tool ${tool.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    if (enabledTools.length === 0) {
      throw new Error('None of the requested tools are available');
    }

    const toolPromises = enabledTools.map(tool => this.runToolSafely(tool, repoPath, options));
    const results = await Promise.allSettled(toolPromises);

    const successfulResults: ToolResult[] = [];
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        successfulResults.push(result.value);
      }
    });

    return successfulResults;
  }

  getAvailableTools(): SecurityTool[] {
    return Array.from(this.tools.values());
  }

  getRegisteredToolNames(): string[] {
    return Array.from(this.tools.keys());
  }

  getTool(name: string): SecurityTool | undefined {
    return this.tools.get(name);
  }

  unregisterTool(name: string): boolean {
    const removed = this.tools.delete(name);
    if (removed) {
      console.log(`Unregistered security tool: ${name}`);
    }
    return removed;
  }

  clearTools(): void {
    const count = this.tools.size;
    this.tools.clear();
    console.log(`Cleared ${count} registered tools`);
  }

  private async runToolSafely(tool: SecurityTool, repoPath: string, options?: ToolOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      console.log(`Starting ${tool.name} analysis...`);
      
      // Apply timeout if configured
      const timeout = options?.timeout || this.configManager.getTimeout();
      const toolPromise = tool.execute(repoPath, options);
      
      let result: ToolResult;
      if (timeout > 0) {
        result = await Promise.race([
          toolPromise,
          this.createTimeoutPromise(timeout, tool.name)
        ]);
      } else {
        result = await toolPromise;
      }

      const executionTime = Date.now() - startTime;
      result.executionTime = executionTime;
      
      console.log(`${tool.name} completed in ${executionTime}ms, found ${result.vulnerabilities.length} vulnerabilities`);
      return result;
      
    } catch (error) {
      const executionTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      console.error(`${tool.name} failed after ${executionTime}ms: ${errorMessage}`);
      
      // Return a failed result instead of throwing
      return {
        toolName: tool.name,
        toolVersion: tool.version,
        executionTime,
        vulnerabilities: [],
        errors: [errorMessage],
        metadata: { failed: true, error: errorMessage }
      };
    }
  }

  private createTimeoutPromise(timeout: number, toolName: string): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Tool ${toolName} timed out after ${timeout}ms`));
      }, timeout);
    });
  }
}