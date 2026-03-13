#!/usr/bin/env python3
"""
Reconnaissance Script for Kali Linux / Arch Linux / BlackArch
Uses: nmap, autorecon, recon-ng, subfinder, ffuf
Auto-detects OS and installs missing dependencies
"""

import argparse
import os
import subprocess
import sys
import re
from datetime import datetime
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class DistroFamily(Enum):
    """Supported distribution families."""
    DEBIAN = "debian"
    ARCH = "arch"
    UNKNOWN = "unknown"


def parse_target(target):
    """Parse URL/target and extract hostname and port for nmap."""
    # Handle URLs with protocol
    if target.startswith('http://') or target.startswith('https://'):
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        port = parsed.port
        return hostname, port
    # Handle hostname:port format
    elif ':' in target and not target.startswith('['):
        parts = target.rsplit(':', 1)
        if parts[1].isdigit():
            return parts[0], int(parts[1])
        return target, None
    # Plain hostname/IP
    return target, None


def check_root():
    """Check if script is running as root."""
    if os.geteuid() != 0:
        print(f"""{Colors.RED}{Colors.BOLD}
    ╔═══════════════════════════════════════════╗
    ║              ROOT REQUIRED                  ║
    ╚═══════════════════════════════════════════╝
    {Colors.RESET}""")
        print(f"{Colors.RED}[!] This script must be run as root/sudo{Colors.RESET}")
        print("    Tool installation and network scanning require elevated privileges.")
        print("\n    Please run:")
        print(f"    {Colors.CYAN}sudo python3 {sys.argv[0]} -t <target>{Colors.RESET}\n")
        sys.exit(1)
    print(f"{Colors.GREEN}[✓]{Colors.RESET} Running as root")


def banner():
    """Display script banner."""
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════╗
    ║           D4YONE-RECON v2.0               ║
    ║  nmap | autorecon | recon-ng | subfinder  ║
    ║                    | ffuf                 ║
    ╚═══════════════════════════════════════════╝
    {Colors.RESET}""")


def run_command(cmd, capture=False, check=False):
    """Run a shell command."""
    try:
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
            return result.returncode == 0, result.stdout, result.stderr
        else:
            result = subprocess.run(cmd, check=check)
            return result.returncode == 0, "", ""
    except subprocess.CalledProcessError as e:
        return False, "", str(e)
    except FileNotFoundError:
        return False, "", "Command not found"


def detect_distro():
    """Detect Linux distribution family."""
    print(f"\n{Colors.YELLOW}[*] Detecting operating system...{Colors.RESET}")

    # Check for /etc/os-release
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            content = f.read().lower()

        # Arch-based detection
        if 'arch' in content or 'blackarch' in content or 'manjaro' in content:
            print(f"    {Colors.GREEN}[✓]{Colors.RESET} Detected: Arch-based Linux")
            return DistroFamily.ARCH

        # Debian-based detection
        if 'debian' in content or 'kali' in content or 'ubuntu' in content or 'linuxmint' in content:
            print(f"    {Colors.GREEN}[✓]{Colors.RESET} Detected: Debian-based Linux")
            return DistroFamily.DEBIAN

    # Check for Arch-specific files
    if os.path.exists('/etc/arch-release'):
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Detected: Arch Linux")
        return DistroFamily.ARCH

    # Check for BlackArch
    if os.path.exists('/etc/blackarch-release'):
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Detected: BlackArch Linux")
        return DistroFamily.ARCH

    # Check for Kali
    if os.path.exists('/etc/kali-version'):
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Detected: Kali Linux")
        return DistroFamily.DEBIAN

    # Fallback: try package managers
    _, out, _ = run_command(['which', 'pacman'], capture=True)
    if out.strip():
        print(f"    {Colors.YELLOW}[!]{Colors.RESET} Detected: Arch-based (via pacman)")
        return DistroFamily.ARCH

    _, out, _ = run_command(['which', 'apt'], capture=True)
    if out.strip():
        print(f"    {Colors.YELLOW}[!]{Colors.RESET} Detected: Debian-based (via apt)")
        return DistroFamily.DEBIAN

    print(f"    {Colors.RED}[✗]{Colors.RESET} Unknown distribution")
    return DistroFamily.UNKNOWN


def check_blackarch_repo():
    """Check if BlackArch repository is configured."""
    if os.path.exists('/etc/pacman.conf'):
        with open('/etc/pacman.conf', 'r') as f:
            content = f.read()
        return 'blackarch' in content.lower()
    return False


def setup_blackarch_repo():
    """Install BlackArch repository on Arch Linux."""
    print(f"\n{Colors.YELLOW}[!] BlackArch repository not found. Setting up...{Colors.RESET}")

    # Download and install blackarch repo config
    print(f"    {Colors.CYAN}[*] Downloading BlackArch repository config...{Colors.RESET}")

    # Check if curl or wget is available
    _, _, _ = run_command(['which', 'curl'], capture=True)
    downloader = 'curl'

    _, out, _ = run_command(['which', 'wget'], capture=True)
    if not out.strip():
        downloader = 'wget'

    if downloader == 'curl':
        success, _, err = run_command([
            'curl', '-L', '-o', '/tmp/blackarch-repo.sh',
            'https://blackarch.org/strap.sh'
        ])
    else:
        success, _, err = run_command([
            'wget', '-O', '/tmp/blackarch-repo.sh',
            'https://blackarch.org/strap.sh'
        ])

    if not success:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to download BlackArch setup script")
        print(f"    {Colors.YELLOW}[!] Please manually install tools with: pacman -S nmap subfinder ffuf python-pipx{Colors.RESET}")
        return False

    # Make executable and run
    run_command(['chmod', '+x', '/tmp/blackarch-repo.sh'])

    print(f"    {Colors.CYAN}[*] Running BlackArch repository setup...{Colors.RESET}")
    print(f"    {Colors.YELLOW}[!] This requires root privileges{Colors.RESET}")

    # Run the strap script
    success, _, err = run_command(['sudo', 'bash', '/tmp/blackarch-repo.sh'])

    if not success:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to setup BlackArch repository")
        print(f"    {Colors.YELLOW}[!] You may need to manually add the repo or install tools individually{Colors.RESET}")
        return False

    # Update pacman database
    print(f"    {Colors.CYAN}[*] Updating package database...{Colors.RESET}")
    run_command(['sudo', 'pacman', '-Sy'])

    print(f"    {Colors.GREEN}[✓]{Colors.RESET} BlackArch repository configured!")
    return True


def install_tools_arch(tools_to_install):
    """Install tools on Arch/BlackArch."""
    print(f"\n{Colors.YELLOW}[*] Installing missing tools on Arch Linux...{Colors.RESET}")

    # Map tools to Arch package names
    package_map = {
        'nmap': 'nmap',
        'ffuf': 'ffuf',
        'recon-ng': 'recon-ng'
    }

    packages = []
    pipx_tools = []
    go_tools = []

    for tool in tools_to_install:
        if tool == 'autorecon':
            pipx_tools.append(tool)
        elif tool == 'subfinder':
            go_tools.append(tool)
        elif tool in package_map:
            packages.append(package_map[tool])

    # Install pacman packages
    if packages:
        print(f"    {Colors.CYAN}[*] Installing: {' '.join(packages)}{Colors.RESET}")
        success, _, _ = run_command(['sudo', 'pacman', '-S', '--noconfirm'] + packages)
        if not success:
            print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to install some packages")

    # Install pipx if needed
    if pipx_tools:
        print(f"    {Colors.CYAN}[*] Setting up pipx...{Colors.RESET}")
        run_command(['sudo', 'pacman', '-S', '--noconfirm', 'python-pipx'])
        run_command(['pipx', 'ensurepath'])

        for tool in pipx_tools:
            print(f"    {Colors.CYAN}[*] Installing {tool} via pipx...{Colors.RESET}")
            run_command(['pipx', 'install', tool])

    # Install go tools
    if go_tools:
        print(f"    {Colors.CYAN}[*] Installing go tools...{Colors.RESET}")
        success, _, _ = run_command(['which', 'go'])
        if success:
            for tool in go_tools:
                if tool == 'subfinder':
                    print(f"    {Colors.CYAN}[*] Installing subfinder via go...{Colors.RESET}")
                    run_command(['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'])
        else:
            print(f"    {Colors.YELLOW}[!] Go not found, downloading subfinder binary...{Colors.RESET}")
            run_command(['curl', '-L', 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip', '-o', '/tmp/subfinder.zip'])
            run_command(['unzip', '-o', '/tmp/subfinder.zip', '-d', '/usr/local/bin/'])
            run_command(['chmod', '+x', '/usr/local/bin/subfinder'])
            run_command(['rm', '/tmp/subfinder.zip'])

    print(f"    {Colors.GREEN}[✓]{Colors.RESET} Installation complete!")


def install_tools_debian(tools_to_install):
    """Install tools on Debian/Kali using apt."""
    print(f"\n{Colors.YELLOW}[*] Installing missing tools on Debian/Kali...{Colors.RESET}")

    # Map tools to Debian package names (available via apt)
    package_map = {
        'nmap': 'nmap',
        'ffuf': 'ffuf',
        'recon-ng': 'recon-ng',
        'autorecon': 'python3-autorecon',
        'subfinder': 'subfinder'
    }

    packages = []

    for tool in tools_to_install:
        if tool in package_map:
            packages.append(package_map[tool])

    # Update package list first
    print(f"    {Colors.CYAN}[*] Updating package list...{Colors.RESET}")
    run_command(['sudo', 'apt', 'update'])

    # Install all packages at once
    if packages:
        print(f"    {Colors.CYAN}[*] Installing: {' '.join(packages)}{Colors.RESET}")
        success, _, _ = run_command(['sudo', 'apt', 'install', '-y'] + packages)
        if not success:
            print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to install some packages")
            print(f"    {Colors.YELLOW}[!] Some tools may need manual installation{Colors.RESET}")

    print(f"    {Colors.GREEN}[✓]{Colors.RESET} Installation complete!")


def check_tool(tool_name):
    """Check if a tool is installed."""
    try:
        subprocess.run(['which', tool_name], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def check_dependencies(auto_install=False):
    """Check for required tools and install if missing."""
    tools = {
        'nmap': 'nmap',
        'autorecon': 'autorecon',
        'subfinder': 'subfinder',
        'ffuf': 'ffuf',
        'recon-ng': 'recon-ng'
    }

    missing = []
    installed = []

    print(f"\n{Colors.YELLOW}[*] Checking dependencies...{Colors.RESET}")

    for tool, display_name in tools.items():
        if check_tool(tool):
            print(f"    {Colors.GREEN}[✓]{Colors.RESET} {display_name}")
            installed.append(tool)
        else:
            print(f"    {Colors.RED}[✗]{Colors.RESET} {display_name}")
            missing.append(tool)

    if missing:
        print(f"\n{Colors.RED}[!] Missing tools: {', '.join(missing)}{Colors.RESET}")

        if auto_install:
            distro = detect_distro()

            if distro == DistroFamily.UNKNOWN:
                print(f"\n{Colors.RED}[!] Cannot auto-install on unknown distribution{Colors.RESET}")
                print("    Please install manually:")
                for tool in missing:
                    print(f"      - {tool}")
                return False

            elif distro == DistroFamily.ARCH:
                # Check for BlackArch repo
                if not check_blackarch_repo():
                    print(f"\n{Colors.YELLOW}[!] BlackArch repository not configured{Colors.RESET}")
                    response = input("    Set up BlackArch repository? [Y/n]: ").strip().lower()
                    if response in ['', 'y', 'yes']:
                        if setup_blackarch_repo():
                            install_tools_arch(missing)
                            return True
                    else:
                        print(f"    {Colors.YELLOW}[!] Installing from official Arch repos only...{Colors.RESET}")
                        install_tools_arch(missing)
                        return True
                else:
                    print(f"    {Colors.CYAN}[*] BlackArch repository detected{Colors.RESET}")
                    install_tools_arch(missing)
                    return True

            elif distro == DistroFamily.DEBIAN:
                install_tools_debian(missing)
                return True

        return False

    print(f"\n{Colors.GREEN}[✓]{Colors.RESET} All dependencies satisfied!")
    return True


def create_output_dir(target):
    """Create output directory for results."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('http://', '').replace('https://', '').replace('/', '_')
    output_dir = Path.cwd() / f"recon_{safe_target}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def run_nmap(target, output_dir, quick=False):
    """Run nmap scan."""
    print(f"\n{Colors.BLUE}[+] Running nmap scan...{Colors.RESET}")

    output_file = output_dir / "nmap_results.txt"

    # Parse target to extract hostname and port
    hostname, port = parse_target(target)

    # Build nmap command
    cmd = ['nmap', '-sV', '-sC', '--open', '-oN', str(output_file)]
    if not quick:
        cmd.insert(1, '-sU')
    if port:
        cmd.extend(['-p', str(port)])
    cmd.append(hostname)

    try:
        subprocess.run(cmd, check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} nmap failed: {e}")
    except FileNotFoundError:
        print(f"    {Colors.RED}[✗]{Colors.RESET} nmap not found. Run: sudo pacman -S nmap")


def run_autorecon(target, output_dir):
    """Run autorecon."""
    print(f"\n{Colors.BLUE}[+] Running autorecon...{Colors.RESET}")

    output_path = output_dir / "autorecon"
    # autorecon uses --output for output directory
    cmd = ['autorecon', '--output', str(output_path), target]

    try:
        subprocess.run(cmd, check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} autorecon failed: {e}")
    except FileNotFoundError:
        print(f"    {Colors.RED}[✗]{Colors.RESET} autorecon not found. Install with: sudo apt install python3-autorecon")


def run_subfinder(domain, output_dir):
    """Run subfinder for subdomain enumeration."""
    print(f"\n{Colors.BLUE}[+] Running subfinder...{Colors.RESET}")

    output_file = output_dir / "subfinder_results.txt"
    cmd = ['subfinder', '-d', domain, '-o', str(output_file), '-silent']

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} subfinder failed: {e}")
    except FileNotFoundError:
        print(f"    {Colors.RED}[✗]{Colors.RESET} subfinder not found. Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")


def run_ffuf(target, output_dir, wordlist=None):
    """Run ffuf for directory fuzzing."""
    print(f"\n{Colors.BLUE}[+] Running ffuf...{Colors.RESET}")

    if not wordlist:
        wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/ffuf/wordlist/common.txt'
        ]
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break

        if not wordlist:
            print(f"    {Colors.RED}[✗]{Colors.RESET} No wordlist found")
            return

    output_file = output_dir / "ffuf_results.json"
    url_pattern = f"{target}/FUZZ" if not target.endswith('/') else f"{target}FUZZ"

    cmd = [
        'ffuf',
        '-u', url_pattern,
        '-w', wordlist,
        '-o', str(output_file),
        '-of', 'json',
        '-s'
    ]

    try:
        subprocess.run(cmd, check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} ffuf failed: {e}")
    except FileNotFoundError:
        print(f"    {Colors.RED}[✗]{Colors.RESET} ffuf not found. Run: sudo pacman -S ffuf")


def run_recon_ng(target, output_dir):
    """Run recon-ng (interactive setup required)."""
    print(f"\n{Colors.BLUE}[+] Setting up recon-ng workspace...{Colors.RESET}")

    workspace_name = f"recon_{target.replace('.', '_').replace('/', '_')}"

    print(f"    Workspace: {workspace_name}")
    print(f"    {Colors.YELLOW}[!]{Colors.RESET} recon-ng requires interactive setup")
    print("    Run manually: recon-ng")
    print(f"    Then: workspace load {workspace_name}")

    # Save workspace info
    info_file = output_dir / "recon_ng_workspace.txt"
    with open(info_file, 'w') as f:
        f.write(f"Workspace: {workspace_name}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Created: {datetime.now().isoformat()}\n")

    print(f"    {Colors.GREEN}[✓]{Colors.RESET} Workspace info saved to: {info_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Automated Reconnaissance Script for Kali/Arch/BlackArch',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t https://example.com -m nmap,subfinder,ffuf
  %(prog)s -t example.com --quick
  %(prog)s -t example.com -w /path/to/wordlist.txt
  %(prog)s -t example.com --no-install  # Skip auto-installation
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or URL')
    parser.add_argument('-m', '--modules', default='all',
                       help='Comma-separated modules: nmap,autorecon,subfinder,ffuf,recon-ng (default: all)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist for ffuf')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan mode (skip UDP scans)')
    parser.add_argument('--no-install', action='store_true', help='Skip automatic installation of missing tools')
    parser.add_argument('--version', action='version', version='D4YONE-RECON v2.0')
    
    args = parser.parse_args()
    
    banner()
    
    # Check root privileges
    check_root()
    
    # Check and install dependencies
    deps_ok = check_dependencies(auto_install=not args.no_install)
    
    if not deps_ok and not args.no_install:
        print(f"\n{Colors.YELLOW}[!] Some tools may still be missing. Continuing anyway...{Colors.RESET}")
    elif not deps_ok:
        print(f"\n{Colors.RED}[!] Missing tools and auto-install disabled{Colors.RESET}")
        print("    Install manually or run without --no-install")
        sys.exit(1)
    
    # Create output directory
    output_dir = create_output_dir(args.target)
    print(f"\n{Colors.GREEN}[+] Output directory: {output_dir}{Colors.RESET}")
    
    # Parse modules
    if args.modules == 'all':
        modules = ['nmap', 'autorecon', 'subfinder', 'ffuf', 'recon-ng']
    else:
        modules = [m.strip() for m in args.modules.split(',')]
    
    # Extract domain for subfinder
    domain = args.target.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Run selected modules
    for module in modules:
        if module == 'nmap':
            run_nmap(args.target, output_dir, quick=args.quick)
        elif module == 'autorecon':
            run_autorecon(args.target, output_dir)
        elif module == 'subfinder':
            run_subfinder(domain, output_dir)
        elif module == 'ffuf':
            run_ffuf(args.target, output_dir, wordlist=args.wordlist)
        elif module == 'recon-ng':
            run_recon_ng(args.target, output_dir)
        else:
            print(f"\n{Colors.RED}[!] Unknown module: {module}{Colors.RESET}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}=== Reconnaissance Complete ==={Colors.RESET}")
    print(f"Results saved to: {output_dir}")
    print(f"{Colors.CYAN}Review findings and proceed with analysis.{Colors.RESET}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
        sys.exit(1)
