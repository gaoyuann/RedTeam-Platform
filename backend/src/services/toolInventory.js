// Display metadata describes registered handlers; it does not assert runtime health.
const purposes = {
  nmap: '端口与服务探测', whatweb: 'Web 技术指纹识别', gobuster: '目录与 DNS 枚举',
  ffuf: 'Web 路径与参数枚举', httpx: 'HTTP 服务探测', amass: '域名与资产枚举', curl: 'HTTP 请求与响应检查',
  nuclei: '模板化漏洞检测', nikto: 'Web 服务配置与漏洞检测', sqlmap: 'SQL 注入检测',
  hydra: '在线口令测试', john: '口令哈希恢复', hashcat: '口令哈希恢复',
  netexec: '网络服务与凭据测试', 'evil-winrm': 'WinRM 远程操作', 'ssh-exec': 'SSH 远程命令',
  rpcclient: 'RPC 服务查询', msfvenom: '测试载荷生成', shellnoob: 'Shellcode 辅助处理',
  arjun: 'HTTP 参数发现', python3: 'Python 脚本执行', 'web-brute': 'Web 登录口令测试',
  responder: '名称解析与认证流量测试', mitm6: 'IPv6 网络测试',
  cloudmapper: '云资源关系分析', pacu: '云环境测试',
  'system-tools': '系统命令执行', cat: '文件内容读取', whoami: '当前用户查询', id: '用户与组查询',
  uname: '系统信息查询', ping: '网络连通性检查', netstat: '网络连接查询',
  tcpdump: '网络数据包捕获', tshark: '网络数据包捕获与分析',
  cppcheck: 'C / C++ 静态分析', flawfinder: 'C / C++ 风险代码检查',
  'target-request': '目标 HTTP 请求', 'source-code-runner': '源码样例隔离执行',
  upload_shell: '测试文件上传处理', webshell: 'WebShell 交互处理', webshell_health: 'WebShell 连通性检查',
};

// Optional capability groups describe when a registered image is useful.
// Registration alone does not make an image mandatory for every task.
export const imageCapabilities = Object.freeze({
  'rt-recon': '资产探测与枚举',
  'rt-vuln-scan': '漏洞扫描',
  'rt-brute': '口令测试',
  'rt-exploit': '远程操作与载荷生成',
  'rt-web': 'Web 参数与登录测试',
  'rt-credential': '凭据与认证测试',
  'rt-cloud': '云环境测试',
  'rt-system': '系统信息与命令',
  'rt-capture': '网络抓包与分析',
  'rt-sast-c': 'C / C++ 源码检查',
});

export function describeTool(toolId, image, virtual) {
  return {
    purpose: purposes[toolId] || '已注册工具',
    executionMode: virtual ? 'virtual' : image === 'builtin' ? 'builtin' : 'container',
  };
}
