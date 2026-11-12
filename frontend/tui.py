"""
VaultMind v2 Terminal User Interface (`frontend/tui.py`).
Interactive zero-trust console powered by Rich with proper markup escaping,
live 2048-bit Feldman VSS shard tampering commands, and SQLite HMAC verification.
"""

import asyncio
import os
import sys

# Ensure project root is importable when invoked directly as `python3 frontend/tui.py`
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from services.pipeline_service import AgentPipeline


console = Console()
pipeline = AgentPipeline()


def make_header() -> Panel:
    title = Text("VAULTMIND v2: NATIVE C ENCLAVE & ZERO-KNOWLEDGE AI PIPELINE", style="bold green")
    subtitle = Text(
        "C11 memset_s() + GF(2^8) Shamir • 2048-bit Feldman VSS • Paillier PHE + C Lattice RLWE-BFV FHE",
        style="dim cyan",
    )
    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_row(title)
    grid.add_row(subtitle)
    return Panel(grid, border_style="green")


def make_wire_panel(blinded_text: str, bits: int) -> Panel:
    safe_wire = escape(blinded_text)
    body = (
        f"[bold cyan]TRANSMITTED TO CLOUD HOST:[/bold cyan]\n\n"
        f"{safe_wire}\n\n"
        f"[dim]// contains_master_key: false | paillier_modulus: {bits}-bit[/dim]"
    )
    return Panel(Text.from_markup(body), title="[bold cyan]External Network Wire[/bold cyan]", border_style="cyan")


def make_vault_panel(vault_status: dict, receipt: dict = None) -> Panel:
    table = Table(
        title=f"Shards on Disk (k={vault_status['threshold_k']} of n={vault_status['total_nodes_n']} | 2048-bit Feldman VSS)",
        expand=True,
        border_style="purple",
    )
    table.add_column("Node ID", style="bold purple")
    table.add_column("x", style="white")
    table.add_column("Canary f(x)", style="cyan")
    table.add_column("VSS & Quorum Status")

    active_quorum = set(receipt.get("quorum_nodes", [])) if receipt else set()

    for node in vault_status["nodes"]:
        if not node["vss_valid"]:
            st = "[bold red]✘ TAMPER REJECTED (Feldman VSS)[/bold red]"
        elif node["node_id"] in active_quorum:
            st = "[bold green]✔ QUORUM ACTIVE (C Stack)[/bold green]"
        else:
            st = "[green]✔ VSS VERIFIED (Standby)[/green]"
        table.add_row(node["node_id"], str(node["index"]), str(node["canary_y"]), st)

    return Panel(table, title="[bold purple]Native C Enclave & Shard Topology[/bold purple]", border_style="purple")


async def main_loop():
    console.clear()
    console.print(make_header())
    console.print(
        "[dim]Commands: type any prompt, '/corrupt 2', '/restore', '/verify', '/metrics', or 'exit'.[/dim]\n"
    )

    default_prompt = (
        "Evaluate a 15% annual bonus for employee Marcus Vance "
        "(salary: $130,000, rating: 4.9) and commit to database with master key."
    )

    while True:
        user_input = Prompt.ask("[bold green]VaultMind>[/bold green]", default=default_prompt).strip()
        if user_input.lower() in {"exit", "quit", "q"}:
            console.print("[dim]Exiting VaultMind v2 TUI.[/dim]")
            break

        if user_input.startswith("/corrupt"):
            parts = user_input.split()
            idx = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 2
            st = pipeline.enclave.tamper_shard_for_demo(idx)
            pipeline.monitor.record_tamper_simulation(idx)
            console.print(make_vault_panel(st))
            continue

        if user_input == "/restore":
            st = pipeline.enclave.restore_all_shards()
            console.print(make_vault_panel(st))
            continue

        if user_input == "/verify":
            ver = pipeline.enclave.verify_ledger_entries()
            console.print(
                f"[bold green]SQLite Ledger C-Enclave Verification:[/bold green] verified={ver['verified']} "
                f"({len(ver.get('entries', []))} sealed rows checked)"
            )
            continue

        if user_input == "/metrics":
            console.print(pipeline.monitor.snapshot())
            continue

        with console.status("[bold green]Running Blinder, Dual PHE/RLWE-BFV FHE & Native C Enclave...[/bold green]"):
            result = await pipeline.process_prompt(user_input, provider="auto")

        console.clear()
        console.print(make_header())

        safe_client = escape(result["unblinded_result"])
        fhe_line = ""
        if result.get("fhe_computation") and result["fhe_computation"].get("decrypted_outputs"):
            fhe_line = f"\n[bold cyan]FHE Math:[/bold cyan] {escape(str(result['fhe_computation']['decrypted_outputs']))}"

        client_markup = (
            f"[bold green]Decrypted Client Verdict:[/bold green]\n\n"
            f"{safe_client}{fhe_line}\n\n"
            f"[dim]Latency: {result['duration_ms']} ms | Engine: {escape(str(result['provider_used']))}[/dim]"
        )

        top_grid = Table.grid(expand=True, padding=(0, 1))
        top_grid.add_column(ratio=1)
        top_grid.add_column(ratio=1)
        top_grid.add_row(
            Panel(Text.from_markup(client_markup), title="[bold green]Local Client View[/bold green]", border_style="green"),
            make_wire_panel(result["blinded_prompt"], result["paillier_public_key"]["modulus_bits"]),
        )

        console.print(top_grid)
        console.print(make_vault_panel(result["vault_topology"], result.get("enclave_receipt")))


if __name__ == "__main__":
    asyncio.run(main_loop())
