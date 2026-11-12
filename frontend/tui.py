"""
VaultMind v2 Terminal User Interface (`frontend/tui.py`).
Interactive zero-trust console powered by Rich with proper markup escaping,
live 2048-bit Feldman VSS shard tampering commands, and SQLite HMAC verification.
"""

import asyncio
import json
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
        "GF(2^8) Shamir + memset_s() key zeroization • 2048-bit Feldman VSS • "
        "Paillier PHE + RLWE-BFV (leveled, depth 1), N=2048, log q=54",
        style="dim cyan",
    )
    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_row(title)
    grid.add_row(subtitle)
    return Panel(grid, border_style="green")


def _count(value):
    if isinstance(value, (list, tuple, set)):
        return len(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def make_leak_line(wire: dict) -> str:
    """Rich markup for the computed leak check (audit B1). Everything dynamic is escaped."""
    wire = wire or {}
    lc = wire.get("leak_check")
    flagged = [
        label
        for key, label in (
            ("contains_master_key", "master key"),
            ("contains_raw_pii", "raw PII"),
            ("contains_raw_secrets", "raw secrets"),
        )
        if wire.get(key) is True
    ]
    if isinstance(lc, dict):
        spans = _count(lc.get("detected_spans"))
        residual = _count(lc.get("residual_matches"))
        spans_txt = "?" if spans is None else str(spans)
        residual_txt = "?" if residual is None else str(residual)
        bad = (residual is not None and residual > 0) or bool(flagged)
        line = f"Leak check: {spans_txt} spans blinded, {residual_txt} residual matches"
        if bad:
            out = f"[bold red]⚠ {escape(line)}[/bold red]"
            if flagged:
                out += f"\n[red]Flagged: {escape(', '.join(flagged))}[/red]"
        else:
            out = f"[bold green]✔ {escape(line)}[/bold green]"
        note = lc.get("note") or "Blinding is heuristic: wrap unlabeled secrets in <secret>…</secret>."
        return out + f"\n[dim]{escape(str(note))}[/dim]"
    if flagged:
        return f"[bold red]⚠ Backend flags: {escape(', '.join(flagged))}[/bold red]"
    return "[dim]Leak check not reported. Blinding is heuristic: wrap unlabeled secrets in <secret>…</secret>.[/dim]"


def make_wire_panel(result: dict) -> Panel:
    """Show the request actually sent to the provider (audit B4), never a made-up endpoint."""
    wire = result.get("cloud_wire_payload") or {}
    req = wire.get("actual_request")
    blinded = result.get("blinded_prompt") or wire.get("transmitted_prompt") or ""
    bits = (result.get("paillier_public_key") or {}).get("modulus_bits") or wire.get("paillier_phe_modulus_bits")

    if isinstance(req, dict) and req.get("url"):
        body = req.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError:
                pass
        body_txt = body if isinstance(body, str) else json.dumps(body, indent=2, ensure_ascii=False)
        head = f"[bold cyan]{escape(str(req.get('method') or 'POST'))} {escape(str(req['url']))}[/bold cyan]"
        wire_txt = f"{head}\n\n{escape(body_txt)}"
    elif isinstance(req, dict):
        note = f"\n[dim]{escape(str(req['note']))}[/dim]" if req.get("note") else ""
        wire_txt = (
            "[bold green]LOCAL ONLY: offline engine, nothing left this machine[/bold green]"
            f"{note}\n\n[cyan]Blinded prompt processed locally:[/cyan]\n{escape(blinded)}"
        )
    else:
        wire_txt = f"[cyan]Blinded prompt (exact request not reported):[/cyan]\n{escape(blinded)}"

    footer = f"\n\n{make_leak_line(wire)}"
    if bits:
        footer += f"\n[dim]paillier_modulus: {escape(str(bits))}-bit[/dim]"
    return Panel(Text.from_markup(wire_txt + footer), title="[bold cyan]External Network Wire[/bold cyan]", border_style="cyan")


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
            try:
                ver = pipeline.enclave.verify_ledger_entries()
            except Exception as exc:  # keep the TUI alive on backend errors
                console.print(f"[bold red]Ledger verification error:[/bold red] {escape(str(exc))}")
                continue
            style = "bold green" if ver.get("verified") else "bold red"
            console.print(
                f"[{style}]SQLite Ledger C-Enclave Verification:[/{style}] verified={escape(str(ver.get('verified')))} "
                f"({len(ver.get('entries', []))} sealed rows checked)"
            )
            if ver.get("error"):
                console.print(f"[red]{escape(str(ver['error']))}[/red]")
            for row in ver.get("entries", []):
                if row.get("hmac_verified") is False:
                    reason = next(
                        (row.get(k) for k in ("verification_reason", "verify_reason","failure_reason", "reason", "error", "verification_error") if row.get(k)),
                        "HMAC mismatch",
                    )
                    console.print(f"[red]  ✘ row #{escape(str(row.get('id')))}: {escape(str(reason))}[/red]")
            continue

        if user_input == "/metrics":
            console.print(pipeline.monitor.snapshot())
            continue

        try:
            with console.status("[bold green]Running blinder, Paillier PHE / RLWE-BFV & native C enclave...[/bold green]"):
                result = await pipeline.process_prompt(user_input, provider="auto")
        except Exception as exc:  # provider errors (HTTP, timeout, bad JSON) must not crash the TUI
            console.print(
                Panel(
                    Text.from_markup(
                        f"[bold red]Pipeline / LLM provider error:[/bold red]\n{escape(type(exc).__name__)}: {escape(str(exc))}\n\n"
                        "[dim]Nothing was sealed. Check the API key / network, or use the offline engine.[/dim]"
                    ),
                    title="[bold red]Error[/bold red]",
                    border_style="red",
                )
            )
            continue

        console.clear()
        console.print(make_header())

        safe_client = escape(str(result.get("unblinded_result", "")))
        fhe_line = ""
        if result.get("fhe_computation") and result["fhe_computation"].get("decrypted_outputs"):
            fhe_line = f"\n[bold cyan]Homomorphic result:[/bold cyan] {escape(str(result['fhe_computation']['decrypted_outputs']))}"
        phase3 = next(
            (p for p in result.get("audit_trail", []) if str(p.get("phase", "")).startswith("PHASE_3")), None
        )
        parse_warning = ((phase3 or {}).get("details") or {}).get("parse_warning") or result.get("parse_warning")
        if parse_warning:
            fhe_line += f"\n[yellow]⚠ LLM output parse warning: {escape(str(parse_warning))}[/yellow]"

        client_markup = (
            f"[bold green]Decrypted Client Verdict:[/bold green]\n\n"
            f"{safe_client}{fhe_line}\n\n"
            f"[dim]Latency: {escape(str(result.get('duration_ms', '--')))} ms | Engine: {escape(str(result.get('provider_used')))}[/dim]"
        )

        top_grid = Table.grid(expand=True, padding=(0, 1))
        top_grid.add_column(ratio=1)
        top_grid.add_column(ratio=1)
        top_grid.add_row(
            Panel(Text.from_markup(client_markup), title="[bold green]Local Client View[/bold green]", border_style="green"),
            make_wire_panel(result),
        )

        console.print(top_grid)
        if result.get("vault_topology"):
            console.print(make_vault_panel(result["vault_topology"], result.get("enclave_receipt")))


if __name__ == "__main__":
    asyncio.run(main_loop())
