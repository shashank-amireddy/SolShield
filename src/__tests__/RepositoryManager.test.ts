import { GitHubRepositoryManager } from '../core/RepositoryManager';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as os from 'os';

// Mock simple-git
jest.mock('simple-git', () => {
  return jest.fn(() => ({
    clone: jest.fn()
  }));
});

// Mock fs-extra
jest.mock('fs-extra');

describe('GitHubRepositoryManager', () => {
  let repositoryManager: GitHubRepositoryManager;
  let mockGit: any;
  let mockFs: jest.Mocked<typeof fs>;

  beforeEach(() => {
    jest.clearAllMocks();
    repositoryManager = new GitHubRepositoryManager();
    
    // Get the mocked git instance
    const simpleGit = require('simple-git');
    mockGit = simpleGit();
    
    // Get the mocked fs
    mockFs = fs as jest.Mocked<typeof fs>;
  });

  describe('cloneRepository', () => {
    const validUrl = 'https://github.com/user/repo';
    const expectedPath = expect.stringMatching(/solidity-scanner[\/\\]repo-\d+$/);

    it('should successfully clone a valid GitHub repository', async () => {
      mockFs.ensureDir.mockResolvedValue(undefined);
      mockGit.clone.mockResolvedValue(undefined);

      const result = await repositoryManager.cloneRepository(validUrl);

      expect(result).toMatch(expectedPath);
      expect(mockFs.ensureDir).toHaveBeenCalledWith(
        expect.stringMatching(/solidity-scanner$/)
      );
      expect(mockGit.clone).toHaveBeenCalledWith(
        validUrl,
        expect.stringMatching(expectedPath),
        {
          '--depth': 1,
          '--single-branch': null
        }
      );
    });

    it('should reject invalid GitHub URLs', async () => {
      const invalidUrls = [
        'https://gitlab.com/user/repo',
        'https://github.com/user',
        'not-a-url',
        'https://github.com/',
        'ftp://github.com/user/repo'
      ];

      for (const url of invalidUrls) {
        await expect(repositoryManager.cloneRepository(url))
          .rejects.toThrow(`Invalid GitHub URL format: ${url}`);
      }
    });

    it('should handle authentication failures', async () => {
      mockFs.ensureDir.mockResolvedValue(undefined);
      mockGit.clone.mockRejectedValue(new Error('Authentication failed'));
      mockFs.pathExists.mockResolvedValue(false);

      await expect(repositoryManager.cloneRepository(validUrl))
        .rejects.toThrow('Authentication failed. Please ensure you have access to the repository');
    });

    it('should handle repository not found errors', async () => {
      mockFs.ensureDir.mockResolvedValue(undefined);
      mockGit.clone.mockRejectedValue(new Error('Repository not found'));
      mockFs.pathExists.mockResolvedValue(false);

      await expect(repositoryManager.cloneRepository(validUrl))
        .rejects.toThrow('Repository not found: https://github.com/user/repo');
    });

    it('should handle network errors', async () => {
      mockFs.ensureDir.mockResolvedValue(undefined);
      mockGit.clone.mockRejectedValue(new Error('Network timeout'));
      mockFs.pathExists.mockResolvedValue(false);

      await expect(repositoryManager.cloneRepository(validUrl))
        .rejects.toThrow('Network error while cloning repository');
    });

    it('should cleanup on clone failure', async () => {
      mockFs.ensureDir.mockResolvedValue(undefined);
      mockGit.clone.mockRejectedValue(new Error('Clone failed'));
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.remove.mockResolvedValue(undefined);

      await expect(repositoryManager.cloneRepository(validUrl))
        .rejects.toThrow('Failed to clone repository');

      expect(mockFs.pathExists).toHaveBeenCalled();
      expect(mockFs.remove).toHaveBeenCalled();
    });

    it('should accept GitHub URLs with .git extension', async () => {
      const urlWithGit = 'https://github.com/user/repo.git';
      mockFs.ensureDir.mockResolvedValue(undefined);
      mockGit.clone.mockResolvedValue(undefined);

      const result = await repositoryManager.cloneRepository(urlWithGit);

      expect(result).toMatch(expectedPath);
      expect(mockGit.clone).toHaveBeenCalledWith(
        urlWithGit,
        expect.stringMatching(expectedPath),
        expect.any(Object)
      );
    });
  });

  describe('cleanup', () => {
    const testPath = '/tmp/test-repo';

    it('should successfully remove existing directory', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.remove.mockResolvedValue(undefined);

      await repositoryManager.cleanup(testPath);

      expect(mockFs.pathExists).toHaveBeenCalledWith(testPath);
      expect(mockFs.remove).toHaveBeenCalledWith(testPath);
    });

    it('should handle non-existent directory gracefully', async () => {
      mockFs.pathExists.mockResolvedValue(false);

      await repositoryManager.cleanup(testPath);

      expect(mockFs.pathExists).toHaveBeenCalledWith(testPath);
      expect(mockFs.remove).not.toHaveBeenCalled();
    });

    it('should handle cleanup errors gracefully', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.remove.mockRejectedValue(new Error('Permission denied'));

      // Should not throw, just log warning
      await expect(repositoryManager.cleanup(testPath)).resolves.toBeUndefined();

      expect(mockFs.pathExists).toHaveBeenCalledWith(testPath);
      expect(mockFs.remove).toHaveBeenCalledWith(testPath);
    });
  });

  describe('findSolidityFiles', () => {
    const testRepoPath = '/test/repo';

    it('should find Solidity files in repository', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.readdir.mockImplementation((dirPath: string) => {
        if (dirPath === testRepoPath) {
          return Promise.resolve([
            { name: 'Contract.sol', isFile: () => true, isDirectory: () => false },
            { name: 'src', isFile: () => false, isDirectory: () => true },
            { name: 'README.md', isFile: () => true, isDirectory: () => false }
          ] as any);
        } else if (dirPath === path.join(testRepoPath, 'src')) {
          return Promise.resolve([
            { name: 'Token.sol', isFile: () => true, isDirectory: () => false },
            { name: 'utils', isFile: () => false, isDirectory: () => true }
          ] as any);
        } else if (dirPath === path.join(testRepoPath, 'src', 'utils')) {
          return Promise.resolve([
            { name: 'Helper.sol', isFile: () => true, isDirectory: () => false }
          ] as any);
        }
        return Promise.resolve([]);
      });

      const result = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(result).toEqual([
        path.join(testRepoPath, 'Contract.sol'),
        path.join(testRepoPath, 'src', 'Token.sol'),
        path.join(testRepoPath, 'src', 'utils', 'Helper.sol')
      ]);
    });

    it('should skip common directories', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.readdir.mockImplementation((dirPath: string) => {
        if (dirPath === testRepoPath) {
          return Promise.resolve([
            { name: 'Contract.sol', isFile: () => true, isDirectory: () => false },
            { name: 'node_modules', isFile: () => false, isDirectory: () => true },
            { name: '.git', isFile: () => false, isDirectory: () => true },
            { name: 'build', isFile: () => false, isDirectory: () => true },
            { name: 'src', isFile: () => false, isDirectory: () => true }
          ] as any);
        } else if (dirPath === path.join(testRepoPath, 'src')) {
          return Promise.resolve([
            { name: 'Token.sol', isFile: () => true, isDirectory: () => false }
          ] as any);
        }
        return Promise.resolve([]);
      });

      const result = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(result).toEqual([
        path.join(testRepoPath, 'Contract.sol'),
        path.join(testRepoPath, 'src', 'Token.sol')
      ]);
      
      // Verify that skipped directories were not traversed
      expect(mockFs.readdir).not.toHaveBeenCalledWith(path.join(testRepoPath, 'node_modules'));
      expect(mockFs.readdir).not.toHaveBeenCalledWith(path.join(testRepoPath, '.git'));
      expect(mockFs.readdir).not.toHaveBeenCalledWith(path.join(testRepoPath, 'build'));
    });

    it('should handle case-insensitive Solidity file extensions', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.readdir.mockResolvedValue([
        { name: 'Contract.sol', isFile: () => true, isDirectory: () => false },
        { name: 'Token.SOL', isFile: () => true, isDirectory: () => false },
        { name: 'Helper.Sol', isFile: () => true, isDirectory: () => false },
        { name: 'NotSolidity.js', isFile: () => true, isDirectory: () => false }
      ] as any);

      const result = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(result).toEqual([
        path.join(testRepoPath, 'Contract.sol'),
        path.join(testRepoPath, 'Helper.Sol'),
        path.join(testRepoPath, 'Token.SOL')
      ]);
    });

    it('should return empty array when no Solidity files found', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.readdir.mockResolvedValue([
        { name: 'README.md', isFile: () => true, isDirectory: () => false },
        { name: 'package.json', isFile: () => true, isDirectory: () => false }
      ] as any);

      const result = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(result).toEqual([]);
    });

    it('should handle repository path that does not exist', async () => {
      mockFs.pathExists.mockResolvedValue(false);

      await expect(repositoryManager.findSolidityFiles('/nonexistent/path'))
        .rejects.toThrow('Repository path does not exist: /nonexistent/path');
    });

    it('should handle directory read errors gracefully', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.readdir.mockImplementation((dirPath: string) => {
        if (dirPath === testRepoPath) {
          return Promise.resolve([
            { name: 'Contract.sol', isFile: () => true, isDirectory: () => false },
            { name: 'problematic', isFile: () => false, isDirectory: () => true }
          ] as any);
        } else if (dirPath === path.join(testRepoPath, 'problematic')) {
          return Promise.reject(new Error('Permission denied'));
        }
        return Promise.resolve([]);
      });

      // Should not throw, but should log warning and continue
      const result = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(result).toEqual([path.join(testRepoPath, 'Contract.sol')]);
    });

    it('should sort results for consistent ordering', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.readdir.mockResolvedValue([
        { name: 'ZContract.sol', isFile: () => true, isDirectory: () => false },
        { name: 'AContract.sol', isFile: () => true, isDirectory: () => false },
        { name: 'MContract.sol', isFile: () => true, isDirectory: () => false }
      ] as any);

      const result = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(result).toEqual([
        path.join(testRepoPath, 'AContract.sol'),
        path.join(testRepoPath, 'MContract.sol'),
        path.join(testRepoPath, 'ZContract.sol')
      ]);
    });
  });

  describe('readFileContent', () => {
    const testFilePath = '/test/Contract.sol';
    const testContent = 'pragma solidity ^0.8.0;\n\ncontract Test {}';

    it('should successfully read file content', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.stat.mockResolvedValue({ isFile: () => true } as any);
      mockFs.readFile.mockResolvedValue(testContent);

      const result = await repositoryManager.readFileContent(testFilePath);

      expect(result).toBe(testContent);
      expect(mockFs.pathExists).toHaveBeenCalledWith(testFilePath);
      expect(mockFs.stat).toHaveBeenCalledWith(testFilePath);
      expect(mockFs.readFile).toHaveBeenCalledWith(testFilePath, 'utf-8');
    });

    it('should handle non-existent file', async () => {
      mockFs.pathExists.mockResolvedValue(false);

      await expect(repositoryManager.readFileContent('/nonexistent/file.sol'))
        .rejects.toThrow('File does not exist: /nonexistent/file.sol');
    });

    it('should handle directory instead of file', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.stat.mockResolvedValue({ isFile: () => false } as any);

      await expect(repositoryManager.readFileContent('/test/directory'))
        .rejects.toThrow('Path is not a file: /test/directory');
    });

    it('should handle file read errors', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.stat.mockResolvedValue({ isFile: () => true } as any);
      mockFs.readFile.mockRejectedValue(new Error('Permission denied'));

      await expect(repositoryManager.readFileContent(testFilePath))
        .rejects.toThrow('Failed to read file content: Permission denied');
    });

    it('should handle empty files', async () => {
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.stat.mockResolvedValue({ isFile: () => true } as any);
      mockFs.readFile.mockResolvedValue('');

      const result = await repositoryManager.readFileContent(testFilePath);

      expect(result).toBe('');
    });

    it('should handle files with special characters', async () => {
      const specialContent = 'pragma solidity ^0.8.0;\n\n// Special chars: éñ中文🚀\ncontract Test {}';
      mockFs.pathExists.mockResolvedValue(true);
      mockFs.stat.mockResolvedValue({ isFile: () => true } as any);
      mockFs.readFile.mockResolvedValue(specialContent);

      const result = await repositoryManager.readFileContent(testFilePath);

      expect(result).toBe(specialContent);
    });
  });
});