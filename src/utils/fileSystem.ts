import * as fs from "fs-extra";
import * as path from "path";

export interface FileSystemEntry {
  name: string;
  path: string;
  isFile: boolean;
  isDirectory: boolean;
}

export class FileSystemUtils {
  static async pathExists(filePath: string): Promise<boolean> {
    return fs.pathExists(filePath);
  }

  static async readFile(
    filePath: string,
    encoding: BufferEncoding = "utf-8"
  ): Promise<string> {
    return fs.readFile(filePath, encoding);
  }

  static async stat(filePath: string): Promise<fs.Stats> {
    return fs.stat(filePath);
  }

  static async readDirectory(dirPath: string): Promise<FileSystemEntry[]> {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });

    return entries.map((entry) => ({
      name: entry.name,
      path: path.join(dirPath, entry.name),
      isFile: entry.isFile(),
      isDirectory: entry.isDirectory(),
    }));
  }

  static async ensureDirectory(dirPath: string): Promise<void> {
    return fs.ensureDir(dirPath);
  }

  static async removeDirectory(dirPath: string): Promise<void> {
    return fs.remove(dirPath);
  }

  static joinPath(...paths: string[]): string {
    return path.join(...paths);
  }

  static isAbsolutePath(filePath: string): boolean {
    return path.isAbsolute(filePath);
  }

  static getFileExtension(fileName: string): string {
    return path.extname(fileName).toLowerCase();
  }

  static getBaseName(filePath: string): string {
    return path.basename(filePath);
  }

  static getDirName(filePath: string): string {
    return path.dirname(filePath);
  }
}
