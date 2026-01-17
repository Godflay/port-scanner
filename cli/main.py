from __future__ import annotations
import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from audit.analyzer import AnalyzeOptions, analyze_port_output, critical_ports
from audit.models import Risk, ListeningPort
from audit.scanner import scan_listening_ports, ScannerError, scan_text_or_raise

app = typer.Typer(add_completion=False)
console = Console()

def _parse_risk(value: Optional[str]) -> Optional[Risk]:
    if value is None:
        return None
    
    value = value.strip().lower()

    try:
        return Risk(value)
    
    except KeyError:
        valid = ", ".join([r.value for r in Risk])
        raise typer.BadParameter(f"Invalid risk level '{value}'. Valid values are: {valid}")
    
def _render_table(ports: list[ListeningPort]) -> None:
    table = Table(title="Listening Ports Audit", show_lines=False)

    table.add_column("PROCESS", overflow="fold")
    table.add_column("PID", justify="right")
    table.add_column("PROTO")
    table.add_column("IP")
    table.add_column("PORT", justify="right")
    table.add_column("EXPOSURE")
    table.add_column("RISK")
    table.add_column("REASON", overflow="fold")

    for port in ports:
        process = port.process.name if port.process else "-"
        pid = str(port.process.pid) if port.process else "-"
        table.add_row(
            process,
            pid,
            port.protocol.value,
            port.address.ip,
            str(port.address.port),
            port.exposure.value,
            port.risk.value,
            port.reason or "-"
        )
    console.print(table)

@app.command()
def status(
    exposed_only: bool = typer.Option(
        False, "--exposed-only", help="Show only exposed LAN/Public ports"
    ),
    min_risk: Optional[str] = typer.Option(
        None, "--min-risk", help="filter to minimum risk: low, medium, high, critical"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results in JSON format"
    ),
    strict: bool = typer.Option(
        True, "--strict/--no-strict", help="strict mode errrors on non-zero exit codes"
    )
) -> None:
    """
    Audit listening network ports on the system
    exit codes:
    0 = ok (no critical ports)
    1 = scaner,parser error
    2 = critical ports found
    """
    try:
        result = scan_listening_ports()
        if strict:
            output = scan_text_or_raise(result)
        else:
            output = result.stdout # allow partial output
        
        options = AnalyzeOptions(
            exposed_only=exposed_only,
            min_risk=_parse_risk(min_risk),
            sort_by_risk=True
        )
        ports = analyze_port_output(output, options=options)

        if json_output:
            payload = [p.to_dict() for p in ports]
            console.print(json.dumps(payload))
        else:
            _render_table(ports)
        
        #exit codes
        if critical_ports(ports):
            raise typer.Exit(code=2)
        
    except ScannerError as e:
        console.print(f"[bold red]Scanner error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except typer.Exit as e:
        raise e
    except Exception:
        console.print_exception(show_locals=False)
        raise typer.Exit(code=1)
    
def main()-> None:
    app()

if __name__ == "__main__":
    main()