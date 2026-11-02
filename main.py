import sys

# Pre-flight check for core dependencies to provide friendly feedback
REQUIRED_DEPENDENCIES = ["rich", "requests", "pefile"]
missing_deps = []
for dep in REQUIRED_DEPENDENCIES:
    try:
        __import__(dep)
    except ImportError:
        missing_deps.append(dep)

if missing_deps:
    print(f"\n[-] Missing required Python dependency: {', '.join(missing_deps)}")
    print(f"[*] Please install the framework dependencies inside your active environment:")
    print(f"    pip install -r requirements.txt\n")
    sys.exit(1)

from pathlib import Path
from rich.console import Console
from core.analyzer import SafeVectorAnalyzer

console = Console()

def main():
    if len(sys.argv) < 2:
        console.print("\n[bold red]Usage:[/bold red] python main.py <target_artifact>\n", style="red")
        console.print("[dim]Black Ant operates in deep single-file triage mode.[/dim]")
        sys.exit(1)

    raw_arg = sys.argv[1].strip().strip('\'"')
    target_path = Path(raw_arg)

    # On Windows, paths starting with '\' or '/' without a drive letter (e.g. \amostras\...)
    # are anchored at drive root (C:\amostras\...). If not found at drive root,
    # resolve relative to current working directory.
    if not target_path.exists() and raw_arg.startswith(("\\", "/")):
        rel_candidate = Path.cwd() / raw_arg.lstrip("\\/")
        if rel_candidate.exists():
            target_path = rel_candidate

    if not target_path.exists():
        console.print(f"\n[bold red][-] Error:[/bold red] File not found: {raw_arg}\n", style="red")
        sys.exit(1)

    target_path = target_path.resolve()

    if target_path.is_dir():
        console.print(f"\n[bold red][-] Error:[/bold red] '{target_path}' is a directory.")
        console.print("[yellow][!] Black Ant operates exclusively in Deep Single-File Triage mode.[/yellow]")
        console.print("[dim]Please specify a single suspicious artifact or vector file (e.g., .exe, .jar, .lnk, .doc, .ps1).\n[/dim]")
        sys.exit(1)

    if not target_path.is_file():
        console.print(f"\n[bold red][-] Error:[/bold red] '{target_path}' is not a regular file.\n", style="red")
        sys.exit(1)

    # Deep Single-File Triage Mode
    analyzer = SafeVectorAnalyzer(str(target_path), interactive=True)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
