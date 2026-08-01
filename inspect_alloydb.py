#!/usr/bin/env python3
"""
Simple script to inspect AlloyDB/PostgreSQL database tables and sample rows.
"""

import json
import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row
from rich import box
from rich.console import Console
from rich.table import Table


console = Console()


def inspect_database():
    load_dotenv(Path(__file__).parent / ".env")

    host = os.environ.get("ALLOYDB_HOST", "localhost")
    port = int(os.environ.get("ALLOYDB_PORT", "5432"))
    database = os.environ.get("ALLOYDB_DATABASE", "secops")
    user = os.environ.get("ALLOYDB_USER", "postgres")
    password = os.environ.get("ALLOYDB_PASSWORD", "password")
    sslmode = os.environ.get("ALLOYDB_SSLMODE", "prefer")

    console.print(
        f"[bold blue]Connecting to {database} on {host}:{port} as {user}...[/bold blue]\n"
    )

    with psycopg.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
        sslmode=sslmode,
    ) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # 1. List all public tables
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name;
            """
            )
            tables = [row["table_name"] for row in cur.fetchall()]

            if not tables:
                console.print("[yellow]No tables found in public schema.[/yellow]")
                return

            console.print(
                f"[bold green]Found {len(tables)} table(s):[/bold green] {', '.join(tables)}\n"
            )

            # 2. Sample 3 rows from each table
            for table_name in tables:
                cur.execute(f"SELECT COUNT(*) AS total FROM {table_name};")  # noqa: S608
                count_row = cur.fetchone()
                total_rows = count_row["total"] if count_row else 0

                cur.execute(f"SELECT * FROM {table_name} LIMIT 3;")  # noqa: S608
                rows = cur.fetchall()

                table_ui = Table(
                    title=f"Table: [bold cyan]{table_name}[/bold cyan] (Total Rows: {total_rows}, Showing 3)",
                    box=box.ROUNDED,
                )

                if not rows:
                    console.print(table_ui)
                    console.print("[dim]  (Table is empty)[/dim]\n")
                    continue

                # Check if embedding column exists and report embedding statistics
                if "embedding" in [k.lower() for k in rows[0].keys()]:
                    cur.execute(
                        f"SELECT COUNT(*) AS embedded FROM {table_name} WHERE embedding IS NOT NULL;"  # noqa: S608
                    )
                    emb_count = cur.fetchone()["embedded"]
                    console.print(
                        f"  [bold yellow]Vector Embeddings:[/bold yellow] {emb_count}/{total_rows} rows embedded (768-dim pgvector)"
                    )

                # Add columns from first row keys
                columns = list(rows[0].keys())
                display_cols = [c for c in columns if c != "embedding"][:7]
                if "embedding" in columns:
                    display_cols.append("embedding")

                for col in display_cols:
                    table_ui.add_column(
                        col, style="white", overflow="ellipsis", max_width=35
                    )

                for r in rows:
                    row_vals = []
                    for col in display_cols:
                        val = r[col]
                        if val is None:
                            val_str = "[dim]NULL[/dim]"
                        elif col == "embedding":
                            val_str = "[bold green][768-dim vector][/bold green]"
                        elif isinstance(val, (dict, list)):
                            val_str = json.dumps(val)
                            if len(val_str) > 40:
                                val_str = val_str[:37] + "..."
                        else:
                            val_str = str(val).replace("\n", " ")
                            if len(val_str) > 40:
                                val_str = val_str[:37] + "..."
                        row_vals.append(val_str)
                    table_ui.add_row(*row_vals)

                console.print(table_ui)
                console.print()


if __name__ == "__main__":
    inspect_database()
