import hashlib
import requests
import json
import os
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

CONFIG_FILE = "config.json"
console = Console()

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def print_banner():
    banner_text = Text("""
██╗  ██╗███████╗██╗  ██╗ █████╗     ██╗  ██╗    ██╗   ██╗████████╗
██║  ██║██╔════╝╚██╗██╔╝██╔══██╗    ╚██╗██╔╝    ██║   ██║╚══██╔══╝
███████║█████╗   ╚███╔╝ ███████║     ╚███╔╝     ██║   ██║   ██║
██╔══██║██╔══╝   ██╔██╗ ██╔══██║     ██╔██╗     ╚██╗ ██╔╝   ██║
██║  ██║███████╗██╔╝ ██╗██║  ██║    ██╔╝ ██╗     ╚████╔╝    ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝      ╚═══╝     ╚═╝
""", style="bold cyan")
    console.print(banner_text)
    console.print(Panel("[bold green]Static Analysis Tool[/bold green]\n[italic yellow]Made by hexsh1dow[/italic yellow]",
                        style="bold cyan", title="Welcome", title_align="center"))
def Credit():
    clear()
    print("""
[+] Author : hexsh1dow
[+] Tool :

""")
    input("Press Enter To Continue")

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            return json.load(file).get("api_key", "")
    return ""

def save_api_key(api_key):
    with open(CONFIG_FILE, "w") as file:
        json.dump({"api_key": api_key}, file)

def calculate_file_hashes(file_path):
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                for algo in hashes.values():
                    algo.update(chunk)
        return {name: algo.hexdigest() for name, algo in hashes.items()}
    except FileNotFoundError:
        return None

def check_hash_in_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"Error": f"VirusTotal API Error: {response.status_code}"}

def display_virustotal_results(file_hash, virustotal_results):
    if "Error" in virustotal_results:
        console.print(Panel(f"[bold red]Error: {virustotal_results['Error']}[/bold red]", title="VirusTotal Result"))
        return False

    data = virustotal_results.get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    table = Table(title="[bold cyan]VirusTotal Detailed Analysis[/bold cyan]")
    table.add_column("[bold green]Engine[/bold green]", justify="left", style="cyan")
    table.add_column("[bold green]Result[/bold green]", justify="center", style="magenta")

    for engine, result in data.get("last_analysis_results", {}).items():
        table.add_row(engine, result.get("result", "Clean"))

    console.print(
        Panel(
            f"File Hash (MD5): [bold green]{file_hash}[/bold green]\n"
            f"Malicious Detections: [bold red]{malicious}[/bold red] / [bold green]{total}[/bold green]",
            title="VirusTotal Summary",
            style="bold green" if malicious == 0 else "bold red",
        )
    )
    console.print(table)
    return True

def main_menu():
    while True:
        clear()
        print_banner()

        console.print("[bold blue]1.[/bold blue] [bold cyan]Analyze a File[/bold cyan]")
        console.print("[bold blue]2.[/bold blue] [bold cyan]Set API Key[/bold cyan]")
        console.print("[bold blue]3.[/bold blue] [bold cyan]Credit[/bold cyan]")
        console.print("[bold blue]0.[/bold blue] [bold cyan]Exit[/bold cyan]")

        choice = Prompt.ask("[bold yellow]Choose an option[/bold yellow]", choices=["0","1", "2", "3"], default="1")
        if choice == "1":
            analyze_file()
        elif choice == "2":
            set_api_key()
        elif choice == "3":
            Credit()
        elif choice == "0":
            console.print("[bold green]Thank you for using the tool! Goodbye![/bold green]")
            break

def analyze_file():
    api_key = load_api_key()
    if not api_key:
        console.print("[bold red]No API key found! Please set it first.[/bold red]")
        return

    file_path = Prompt.ask("[bold yellow]Enter the path of the file to analyze[/bold yellow]")
    file_hashes = calculate_file_hashes(file_path)

    if not file_hashes:
        console.print(f"[bold red]Error: File not found at {file_path}[/bold red]")
        return

    console.print(Panel(
        f"[bold cyan]MD5:[/bold cyan] [bold green]{file_hashes['md5']}[/bold green]\n"
        f"[bold cyan]SHA1:[/bold cyan] [bold green]{file_hashes['sha1']}[/bold green]\n"
        f"[bold cyan]SHA256:[/bold cyan] [bold green]{file_hashes['sha256']}[/bold green]",
        title="File Hashes",
        style="bold magenta",
    ))

    console.print("[bold yellow]Using MD5 hash for VirusTotal analysis...[/bold yellow]")
    virustotal_results = check_hash_in_virustotal(file_hashes["md5"], api_key)

    if not display_virustotal_results(file_hashes["md5"], virustotal_results):
        console.print(Panel("[bold yellow]No VirusTotal results found. You can try again later or analyze another file.[/bold yellow]",
                            style="bold cyan", title="Info"))

    Prompt.ask("[bold green]Press Enter to return to the main menu[/bold green]")

def set_api_key():
    api_key = Prompt.ask("[bold green]Enter your VirusTotal API key[/bold green]")
    save_api_key(api_key)
    console.print("[bold green]API key saved successfully![/bold green]")

if __name__ == "__main__":
    main_menu()
