import { constants } from 'node:fs';
import { lstat, open, mkdir, chmod, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
import { ToolError } from './security.js';

type AclAction = 'verify' | 'restrict';
type Acl = (path: string, action: AclAction, directory: boolean) => void;

// Paths travel through the environment, never through PowerShell source interpolation.
export const windowsAcl: Acl = (path, action, directory) => {
  const script = `
$ErrorActionPreference = 'Stop'
$p = $env:UNIFI_AXI_PRIVATE_PATH
$item = Get-Item -LiteralPath $p -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse point' }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
if ($env:UNIFI_AXI_ACL_ACTION -eq 'restrict') {
  if ($env:UNIFI_AXI_ACL_DIRECTORY -eq 'true') {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  } else {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $inherit = [Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetOwner($user)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($user, $system, $admins)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit, 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $p -AclObject $acl
} else {
  $acl = Get-Acl -LiteralPath $p
  if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value) { throw 'unprotected ACL or owner' }
  $allowed = @($user.Value, $system.Value, $admins.Value)
  $granted = @()
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin $allowed -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'unexpected grant' }
    $granted += $rule.IdentityReference.Value
  }
  foreach ($sid in $allowed) { if ($sid -notin $granted) { throw 'missing grant' } }
}
`;
  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    env: { ...process.env, UNIFI_AXI_PRIVATE_PATH: path, UNIFI_AXI_ACL_ACTION: action, UNIFI_AXI_ACL_DIRECTORY: String(directory) },
    stdio: 'pipe', timeout: 10_000,
  });
};

export class PrivateFiles {
  constructor(private readonly platform = process.platform, private readonly acl: Acl = windowsAcl) {}

  private insecure(path: string): ToolError {
    return new ToolError('CONFIG_INSECURE', `Unsafe private file: ${path}. ${this.platform === 'win32' ? 'Re-run profile configure to apply a protected Windows ACL.' : `Use chmod 600 '${path}'.`}`);
  }

  async directory(path: string, exclusive = false): Promise<void> {
    await mkdir(path, { recursive: !exclusive, mode: 0o700 });
    await this.verifyDirectory(path);
    if (this.platform === 'win32') this.acl(path, 'restrict', true);
    for (let current = path; ; current = dirname(current)) {
      await this.syncDirectory(current);
      if (current === dirname(current)) break;
    }
  }

  async verifyDirectory(path: string): Promise<void> {
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() ||
        (this.platform !== 'win32' && (stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0))) throw this.insecure(path);
    if (this.platform === 'win32') this.acl(path, 'verify', true);
  }

  async syncDirectory(path: string): Promise<void> {
    // Windows FlushFileBuffers does not support directory handles through Node.
    // Keep native Windows writes unavailable until that durability boundary is proven.
    if (this.platform === 'win32') throw new ToolError('WRITE_UNSUPPORTED', 'Durable native Windows writes are pending verification.');
    const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }

  async read(path: string, secret = false): Promise<string> {
    const before = await lstat(path);
    if (!before.isFile() || before.isSymbolicLink()) throw this.insecure(path);
    if (this.platform === 'win32') {
      try { this.acl(path, 'verify', false); } catch { throw this.insecure(path); }
    } else if (before.uid !== process.getuid!() || (before.mode & (secret ? 0o077 : 0o022)) !== 0) {
      throw this.insecure(path);
    }
    const handle = await open(path, constants.O_RDONLY | (this.platform === 'win32' ? 0 : constants.O_NOFOLLOW));
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || before.dev !== opened.dev || before.ino !== opened.ino ||
          (this.platform !== 'win32' && (opened.uid !== process.getuid!() || (opened.mode & (secret ? 0o077 : 0o022)) !== 0))) throw this.insecure(path);
      return await handle.readFile('utf8');
    } finally { await handle.close(); }
  }

  async create(path: string, content: () => Promise<string>): Promise<void> {
    // Reserve exclusively before reading secrets; never replace an existing destination.
    await this.verifyDirectory(dirname(path));
    const handle = await open(path, 'wx', 0o600).catch(error => {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new ToolError('OUTPUT_EXISTS', 'The secret output destination already exists. Choose a new file.');
      throw error;
    });
    try {
      if (this.platform === 'win32') {
        this.acl(path, 'restrict', false);
        this.acl(path, 'verify', false);
      }
      await handle.writeFile(await content(), 'utf8');
      await handle.sync();
    } catch (error) {
      await unlink(path);
      throw error;
    } finally { await handle.close(); }
  }

  async write(path: string, content: string): Promise<void> {
    const parent = dirname(path);
    await mkdir(parent, { recursive: true, mode: 0o700 });
    const directory = await lstat(parent);
    if (!directory.isDirectory() || directory.isSymbolicLink() || (this.platform !== 'win32' && directory.uid !== process.getuid!())) throw this.insecure(parent);
    if (this.platform === 'win32') {
      try { this.acl(parent, 'restrict', true); } catch { throw this.insecure(parent); }
    } else await chmod(parent, 0o700);
    const temporary = join(parent, `.unifi-${randomUUID()}.tmp`);
    const handle = await open(temporary, 'wx', 0o600);
    try {
      if (this.platform === 'win32') {
        try { this.acl(temporary, 'restrict', false); } catch { throw this.insecure(temporary); }
      }
      await handle.writeFile(content, 'utf8');
      await handle.sync();
      await handle.close();
      const deadline = Date.now() + 1000;
      for (;;) {
        try { await rename(temporary, path); break; } catch (error) {
          if (this.platform !== 'win32' || !['EPERM', 'EBUSY', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '') || Date.now() >= deadline) throw error;
          await setTimeout(50);
        }
      }
    } finally {
      await handle.close();
      await unlink(temporary).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; });
    }
  }
}
