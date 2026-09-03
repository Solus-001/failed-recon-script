#!/usr/bin/env python3
"""
Reconnaissance Script for Kali Linux / Arch Linux / BlackArch
Uses: nmap, autorecon, recon-ng, subfinder, ffuf
Auto-detects OS and installs missing dependencies
"""

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
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


# Modules that require root (raw sockets / privileged scans).
PRIVILEGED_MODULES = {'nmap', 'autorecon'}

VALID_MODULES = ('nmap', 'autorecon', 'subfinder', 'ffuf', 'recon-ng')


def parse_target(target):
    """Parse URL/target and extract hostname and port for nmap.

    Handles http(s)://host[:port][/path], host:port, bare host/IP,
    and bracketed IPv6 ([::1] / [::1]:8080).
    Returns (hostname, port_or_None).
    """
    target = target.strip()
    if target.startswith('http://') or target.startswith('https://'):
        parsed = urlparse(target)
        return parsed.hostname or target, parsed.port
    # Bracketed IPv6: [::1] or [::1]:8080
    if target.startswith('['):
        end = target.find(']')
        if end != -1:
            host = target[1:end]
            rest = target[end + 1:]
            if rest.startswith(':') and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
        return target, None
    # hostname:port / IPv4:port (only when a single trailing :digits)
    if ':' in target and target.count(':') == 1:
        host, _, port = target.partition(':')
        if port.isdigit():
            return host, int(port)
        return target, None
    # Plain hostname/IP (or unbracketed IPv6 -> leave whole)
    return target, None


def is_ip_address(value):
    """Return True if value is an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_domain(target):
    """Extract bare host without port/path for subfinder/recon-ng."""
    hostname, _ = parse_target(target)
    # parse_target never returns brackets, but be safe
    return hostname.strip('[]')


def ensure_http_url(target):
    """Return target with an http(s) scheme for ffuf."""
    target = target.strip()
    if not target.startswith('http://') and not target.startswith('https://'):
        return 'http://' + target
    return target


def check_root():
    """Check if script is running as root."""
    if os.geteuid() != 0:
        print(f"""{Colors.RED}{Colors.BOLD}
    ╔═══════════════════════════════════════════╗
    ║              ROOT REQUIRED                ║
    ╚═══════════════════════════════════════════╝
    {Colors.RESET}""")
        print(f"{Colors.RED}[!] This scan needs root/sudo (nmap/autorecon){Colors.RESET}")
        print("    Tool installation and network scanning require elevated privileges.")
        print("\n    Please run:")
        print(f"    {Colors.CYAN}sudo python3 {sys.argv[0]} -t <target>{Colors.RESET}\n")
        sys.exit(1)
    print(f"{Colors.GREEN}[✓]{Colors.RESET} Running as root")


def banner():
    """Display script banner."""
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════╗
    ║           D4YONE-RECON v2.1               ║
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
    if shutil.which('pacman'):
        print(f"    {Colors.YELLOW}[!]{Colors.RESET} Detected: Arch-based (via pacman)")
        return DistroFamily.ARCH

    if shutil.which('apt'):
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


def pick_downloader():
    """Pick an available downloader: curl preferred, wget fallback."""
    if shutil.which('curl'):
        return 'curl'
    if shutil.which('wget'):
        return 'wget'
    return None


def setup_blackarch_repo():
    """Install BlackArch repository on Arch Linux."""
    print(f"\n{Colors.YELLOW}[!] BlackArch repository not found. Setting up...{Colors.RESET}")

    downloader = pick_downloader()
    if downloader is None:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Neither curl nor wget found.")
        print(f"    {Colors.YELLOW}[!] Install one first: pacman -S curl{Colors.RESET}")
        return False

    print(f"    {Colors.CYAN}[*] Downloading BlackArch repository config (via {downloader})...{Colors.RESET}")
    if downloader == 'curl':
        success, _, _ = run_command([
            'curl', '-L', '-o', '/tmp/blackarch-repo.sh',
            'https://blackarch.org/strap.sh'
        ])
    else:
        success, _, _ = run_command([
            'wget', '-O', '/tmp/blackarch-repo.sh',
            'https://blackarch.org/strap.sh'
        ])

    if not success:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to download BlackArch setup script")
        print(f"    {Colors.YELLOW}[!] Please manually install tools with: pacman -S nmap ffuf recon-ng python-pipx{Colors.RESET}")
        return False

    # Make executable and run (already root here; no sudo indirection)
    run_command(['chmod', '+x', '/tmp/blackarch-repo.sh'])

    print(f"    {Colors.CYAN}[*] Running BlackArch repository setup...{Colors.RESET}")

    success, _, err = run_command(['bash', '/tmp/blackarch-repo.sh'])
    if not success:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to setup BlackArch repository: {err}")
        print(f"    {Colors.YELLOW}[!] You may need to manually add the repo or install tools individually{Colors.RESET}")
        return False

    # Update pacman database
    print(f"    {Colors.CYAN}[*] Updating package database...{Colors.RESET}")
    run_command(['pacman', '-Sy'])

    print(f"    {Colors.GREEN}[✓]{Colors.RESET} BlackArch repository configured!")
    return True


def install_tools_arch(tools_to_install):
    """Install tools on Arch/BlackArch. Returns True if all present after."""
    print(f"\n{Colors.YELLOW}[*] Installing missing tools on Arch Linux...{Colors.RESET}")

    # Map tools to Arch package names
    package_map = {
        'nmap': 'nmap',
        'ffuf': 'ffuf',
        'recon-ng': 'recon-ng',
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
        success, _, _ = run_command(['pacman', '-S', '--noconfirm'] + packages)
        if not success:
            print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to install some packages")

    # Install pipx if needed
    if pipx_tools:
        print(f"    {Colors.CYAN}[*] Setting up pipx...{Colors.RESET}")
        run_command(['pacman', '-S', '--noconfirm', 'python-pipx'])
        run_command(['pipx', 'ensurepath'])

        for tool in pipx_tools:
            print(f"    {Colors.CYAN}[*] Installing {tool} via pipx...{Colors.RESET}")
            ok, _, _ = run_command(['pipx', 'install', tool])
            if not ok:  # fall back to pipx upgrade if already installed
                run_command(['pipx', 'upgrade', tool])

    # Install go tools
    if go_tools:
        if shutil.which('go'):
            for tool in go_tools:
                if tool == 'subfinder':
                    print(f"    {Colors.CYAN}[*] Installing subfinder via go...{Colors.RESET}")
                    run_command(['go', 'install', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'])
        elif shutil.which('curl') or shutil.which('wget'):
            print(f"    {Colors.YELLOW}[!] Go not found, downloading subfinder binary...{Colors.RESET}")
            if shutil.which('curl'):
                run_command(['curl', '-L', 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip', '-o', '/tmp/subfinder.zip'])
            else:
                run_command(['wget', '-O', '/tmp/subfinder.zip', 'https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip'])
            run_command(['unzip', '-o', '/tmp/subfinder.zip', '-d', '/usr/local/bin/'])
            run_command(['chmod', '+x', '/usr/local/bin/subfinder'])
            run_command(['rm', '-f', '/tmp/subfinder.zip'])
        else:
            print(f"    {Colors.RED}[✗]{Colors.RESET} Cannot install subfinder: need go, curl, or wget")

    remaining = [t for t in tools_to_install if not check_tool(t)]
    # ~/go/bin and ~/.local/bin often hold go/pipx installs but are not on root's PATH
    if remaining:
        extra_dirs = [str(Path.home() / 'go' / 'bin'), str(Path.home() / '.local' / 'bin')]
        for tool in list(remaining):
            for d in extra_dirs:
                if os.path.exists(os.path.join(d, tool)):
                    print(f"    {Colors.YELLOW}[!]{Colors.RESET} {tool} installed to {d} — add it to PATH")
                    break
    if remaining:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Still missing: {', '.join(remaining)}")
        return False
    print(f"    {Colors.GREEN}[✓]{Colors.RESET} Installation complete!")
    return True


def install_tools_debian(tools_to_install):
    """Install tools on Debian/Kali using apt. Returns True if all present after."""
    print(f"\n{Colors.YELLOW}[*] Installing missing tools on Debian/Kali...{Colors.RESET}")

    # Map tools to Debian package names (available via apt)
    package_map = {
        'nmap': 'nmap',
        'ffuf': 'ffuf',
        'recon-ng': 'recon-ng',
        'autorecon': 'python3-autorecon',
        'subfinder': 'subfinder',
    }

    packages = [package_map[tool] for tool in tools_to_install if tool in package_map]

    # Update package list first
    print(f"    {Colors.CYAN}[*] Updating package list...{Colors.RESET}")
    run_command(['apt', 'update'])

    # Install all packages at once
    if packages:
        print(f"    {Colors.CYAN}[*] Installing: {' '.join(packages)}{Colors.RESET}")
        success, _, _ = run_command(['apt', 'install', '-y'] + packages)
        if not success:
            print(f"    {Colors.RED}[✗]{Colors.RESET} Failed to install some packages")
            print(f"    {Colors.YELLOW}[!] Some tools may need manual installation{Colors.RESET}")

    remaining = [t for t in tools_to_install if not check_tool(t)]
    if remaining:
        print(f"    {Colors.RED}[✗]{Colors.RESET} Still missing: {', '.join(remaining)}")
        return False
    print(f"    {Colors.GREEN}[✓]{Colors.RESET} Installation complete!")
    return True


def check_tool(tool_name):
    """Check if a tool is installed."""
    return shutil.which(tool_name) is not None


def check_dependencies(auto_install=False, only_modules=None):
    """Check for required tools and install if missing.

    only_modules: restrict the check to tools for selected modules.
    Returns True only if every needed tool is present afterwards.
    """
    module_tools = {
        'nmap': ('nmap',),
        'autorecon': ('autorecon',),
        'subfinder': ('subfinder',),
        'ffuf': ('ffuf',),
        'recon-ng': ('recon-ng',),
    }
    if only_modules is None:
        tools = {t: t for mods in module_tools.values() for t in mods}
    else:
        tools = {}
        for mod in only_modules:
            for t in module_tools.get(mod, ()):
                tools[t] = t

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

    if not missing:
        print(f"\n{Colors.GREEN}[✓]{Colors.RESET} All dependencies satisfied!")
        return True

    print(f"\n{Colors.RED}[!] Missing tools: {', '.join(missing)}{Colors.RESET}")

    if not auto_install:
        return False

    distro = detect_distro()

    if distro == DistroFamily.UNKNOWN:
        print(f"\n{Colors.RED}[!] Cannot auto-install on unknown distribution{Colors.RESET}")
        print("    Please install manually:")
        for tool in missing:
            print(f"      - {tool}")
        return False

    if distro == DistroFamily.ARCH:
        # Check for BlackArch repo
        if not check_blackarch_repo():
            print(f"\n{Colors.YELLOW}[!] BlackArch repository not configured{Colors.RESET}")
            response = input("    Set up BlackArch repository? [Y/n]: ").strip().lower()
            if response in ['', 'y', 'yes']:
                if not setup_blackarch_repo():
                    return False
            else:
                print(f"    {Colors.YELLOW}[!] Installing from official Arch repos only...{Colors.RESET}")
        else:
            print(f"    {Colors.CYAN}[*] BlackArch repository detected{Colors.RESET}")
        install_ok = install_tools_arch(missing)
    elif distro == DistroFamily.DEBIAN:
        install_ok = install_tools_debian(missing)
    else:
        return False

    # Re-verify: never claim success without proof
    still_missing = [t for t in missing if not check_tool(t)]
    if still_missing:
        print(f"\n{Colors.RED}[✗]{Colors.RESET} Auto-install incomplete, still missing: {', '.join(still_missing)}")
        return False
    print(f"\n{Colors.GREEN}[✓]{Colors.RESET} All dependencies satisfied after install!")
    return install_ok


def create_output_dir(target):
    """Create output directory for results."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^A-Za-z0-9._-]', '_', target.strip())
    safe_target = safe_target.strip('_')[:100] or 'target'
    output_dir = Path.cwd() / f"recon_{safe_target}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def run_nmap(target, output_dir, quick=False, udp=False):
    """Run nmap scan.

    Default: TCP SYN/SYN+version+scripts on top ports (fast, needs root).
    quick: -F (top 100 ports) + aggressive timing.
    udp: adds a bounded UDP top-ports pass (--top-ports 200), never full range.
    """
    print(f"\n{Colors.BLUE}[+] Running nmap scan...{Colors.RESET}")

    if not check_tool('nmap'):
        print(f"    {Colors.RED}[✗]{Colors.RESET} nmap not found. Install it first (not skipping silently).")
        return

    txt_out = output_dir / "nmap_results.txt"
    xml_out = output_dir / "nmap_results.xml"

    # Parse target to extract hostname and port
    hostname, port = parse_target(target)

    # SYN scan as root, connect scan otherwise
    scan_type = '-sS' if os.geteuid() == 0 else '-sT'
    cmd = ['nmap', scan_type, '-sV', '-sC', '--open',
           '-oN', str(txt_out), '-oX', str(xml_out)]
    if quick:
        cmd.extend(['-F', '-T4', '--min-rate', '1000'])
    else:
        cmd.extend(['-T4'])
    if udp:
        cmd.extend(['-sU', '--top-ports', '200'])
    if port:
        cmd.extend(['-p', str(port)])
    cmd.append(hostname)

    try:
        subprocess.run(cmd, check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {txt_out}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} nmap failed: {e}")


def run_autorecon(target, output_dir):
    """Run autorecon."""
    print(f"\n{Colors.BLUE}[+] Running autorecon...{Colors.RESET}")

    if not check_tool('autorecon'):
        print(f"    {Colors.RED}[✗]{Colors.RESET} autorecon not found. Install with: pipx install autorecon (Arch) / apt install python3-autorecon (Kali)")
        return

    output_path = output_dir / "autorecon"
    hostname, _ = parse_target(target)
    # autorecon takes a bare target; --output sets the results dir
    cmd = ['autorecon', '--output', str(output_path), hostname]

    try:
        subprocess.run(cmd, check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {output_path}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} autorecon failed: {e}")


def run_subfinder(domain, output_dir):
    """Run subfinder for subdomain enumeration."""
    print(f"\n{Colors.BLUE}[+] Running subfinder...{Colors.RESET}")

    if not check_tool('subfinder'):
        print(f"    {Colors.RED}[✗]{Colors.RESET} subfinder not found. Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return

    domain = domain.strip().strip('[]')
    if is_ip_address(domain):
        print(f"    {Colors.YELLOW}[!]{Colors.RESET} Skipping subfinder: target is an IP, not a domain")
        return

    output_file = output_dir / "subfinder_results.txt"
    # No -silent + no capture: stream progress to the terminal
    cmd = ['subfinder', '-d', domain, '-o', str(output_file)]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} subfinder failed: {e}")
        return

    if output_file.exists():
        count = sum(1 for line in output_file.read_text().splitlines() if line.strip())
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Found {count} subdomains. Saved to: {output_file}")
    else:
        print(f"    {Colors.YELLOW}[!]{Colors.RESET} subfinder finished but wrote no output file")


def run_ffuf(target, output_dir, wordlist=None):
    """Run ffuf for directory fuzzing."""
    print(f"\n{Colors.BLUE}[+] Running ffuf...{Colors.RESET}")

    if not check_tool('ffuf'):
        print(f"    {Colors.RED}[✗]{Colors.RESET} ffuf not found. Install with: pacman -S ffuf / apt install ffuf")
        return

    if not wordlist:
        wordlists = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/ffuf/wordlist/common.txt',
        ]
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break

        if not wordlist:
            print(f"    {Colors.RED}[✗]{Colors.RESET} No wordlist found. Pass one with -w /path/to/wordlist.txt")
            return

    if not os.path.exists(wordlist):
        print(f"    {Colors.RED}[✗]{Colors.RESET} Wordlist not found: {wordlist}")
        return
    print(f"    {Colors.CYAN}[*] Wordlist: {wordlist}{Colors.RESET}")

    url = ensure_http_url(target)
    url_pattern = url if url.endswith('/') else url + '/'
    url_pattern += 'FUZZ'

    output_file = output_dir / "ffuf_results.json"

    cmd = [
        'ffuf',
        '-u', url_pattern,
        '-w', wordlist,
        '-o', str(output_file),
        '-of', 'json',
        '-mc', '200,204,301,302,307,401,403,500',
        '-fc', '404',
        '-t', '40',
        '-timeout', '10',
    ]

    try:
        subprocess.run(cmd, check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Results saved to: {output_file}")
    except subprocess.CalledProcessError as e:
        # ffuf exits non-zero when no matches; output file may still hold data
        if output_file.exists():
            print(f"    {Colors.YELLOW}[!]{Colors.RESET} ffuf exited {e.returncode}, partial results at: {output_file}")
        else:
            print(f"    {Colors.RED}[✗]{Colors.RESET} ffuf failed: {e}")


def run_recon_ng(target, output_dir):
    """Run recon-ng non-interactively via a resource script."""
    print(f"\n{Colors.BLUE}[+] Running recon-ng...{Colors.RESET}")

    domain = extract_domain(target)
    workspace_name = re.sub(r'[^A-Za-z0-9_]', '_', f"recon_{domain}")[:63].strip('_') or 'recon_target'

    info_file = output_dir / "recon_ng_workspace.txt"
    rc_file = output_dir / "recon_ng_commands.rc"
    with open(info_file, 'w') as f:
        f.write(f"Workspace: {workspace_name}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Created: {datetime.now().isoformat()}\n")

    if not check_tool('recon-ng'):
        print(f"    {Colors.RED}[✗]{Colors.RESET} recon-ng not found. Install with: pacman -S recon-ng / apt install recon-ng")
        print(f"    Workspace info saved to: {info_file} (run manually: recon-ng, then: workspaces load {workspace_name})")
        return

    # Non-interactive resource script: seed the DB so the run does real work
    if is_ip_address(domain):
        seed = f"db insert hosts {domain}\nshow hosts\n"
    else:
        seed = f"db insert domains {domain}\nshow domains\n"
    rc_file.write_text(
        f"workspaces create {workspace_name}\n"
        f"workspaces load {workspace_name}\n"
        f"{seed}"
        "exit\n"
    )

    try:
        subprocess.run(['recon-ng', '-r', str(rc_file)], check=True)
        print(f"    {Colors.GREEN}[✓]{Colors.RESET} Workspace '{workspace_name}' seeded. Info: {info_file}")
    except subprocess.CalledProcessError as e:
        print(f"    {Colors.RED}[✗]{Colors.RESET} recon-ng failed: {e}")
        print(f"    Run manually: recon-ng, then: workspaces load {workspace_name}")


def parse_modules(raw):
    """Parse/validate -m modules. Returns (modules, unknown)."""
    if raw == 'all':
        return ['nmap', 'autorecon', 'subfinder', 'ffuf', 'recon-ng'], []
    seen, unknown = [], []
    for m in (part.strip().lower() for part in raw.split(',')):
        if not m:
            continue
        if m in VALID_MODULES and m not in seen:
            seen.append(m)
        elif m not in VALID_MODULES and m not in unknown:
            unknown.append(m)
    return seen, unknown


def main():
    parser = argparse.ArgumentParser(
        description='Automated Reconnaissance Script for Kali/Arch/BlackArch',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t https://example.com -m nmap,subfinder,ffuf
  %(prog)s -t example.com --quick
  %(prog)s -t example.com --udp          # add bounded UDP top-ports pass
  %(prog)s -t example.com -w /path/to/wordlist.txt
  %(prog)s -t example.com --no-install  # Skip auto-installation
        """
    )

    parser.add_argument('-t', '--target', required=True, help='Target domain or URL')
    parser.add_argument('-m', '--modules', default='all',
                       help='Comma-separated modules: nmap,autorecon,subfinder,ffuf,recon-ng (default: all)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist for ffuf')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan mode (nmap -F, top 100 ports)')
    parser.add_argument('--udp', action='store_true', help='Add bounded UDP top-ports pass to nmap (default: TCP only)')
    parser.add_argument('--no-install', action='store_true', help='Skip automatic installation of missing tools')
    parser.add_argument('--version', action='version', version='D4YONE-RECON v2.1')

    args = parser.parse_args()

    banner()

    # Parse + validate modules first: root/install scope depends on them
    modules, unknown = parse_modules(args.modules)
    for bad in unknown:
        print(f"\n{Colors.RED}[!] Unknown module: {bad}{Colors.RESET}")
    if not modules:
        print(f"{Colors.RED}[!] No valid modules selected. Valid: {', '.join(VALID_MODULES)}{Colors.RESET}")
        sys.exit(1)

    # Root only when a privileged module or auto-install will run
    needs_root = bool(set(modules) & PRIVILEGED_MODULES) or not args.no_install
    if needs_root:
        check_root()
    else:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Running unprivileged (no nmap/autorecon selected, install skipped)")

    # Check and install dependencies (only for selected modules)
    deps_ok = check_dependencies(auto_install=not args.no_install, only_modules=modules)

    if not deps_ok and not args.no_install:
        print(f"\n{Colors.YELLOW}[!] Some tools may still be missing. Continuing anyway...{Colors.RESET}")
    elif not deps_ok:
        print(f"\n{Colors.RED}[!] Missing tools and auto-install disabled{Colors.RESET}")
        print("    Install manually or run without --no-install")
        sys.exit(1)

    # Create output directory
    output_dir = create_output_dir(args.target)
    print(f"\n{Colors.GREEN}[+] Output directory: {output_dir}{Colors.RESET}")

    # Bare host for domain tools (port/path stripped)
    domain = extract_domain(args.target)

    # Run selected modules
    for module in modules:
        if module == 'nmap':
            run_nmap(args.target, output_dir, quick=args.quick, udp=args.udp)
        elif module == 'autorecon':
            run_autorecon(args.target, output_dir)
        elif module == 'subfinder':
            run_subfinder(domain, output_dir)
        elif module == 'ffuf':
            run_ffuf(args.target, output_dir, wordlist=args.wordlist)
        elif module == 'recon-ng':
            run_recon_ng(args.target, output_dir)

    print(f"\n{Colors.GREEN}{Colors.BOLD}=== Reconnaissance Complete ==={Colors.RESET}")
    print(f"Results saved to: {output_dir}")
    print(f"{Colors.CYAN}Review findings and proceed with analysis.{Colors.RESET}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
        sys.exit(1)
