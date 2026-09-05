"""CLI for spike — батарея промпт-инъекций для LLM-эндпоинтов."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import SPIKE_BANNER
from .payloads import add_custom_payloads, catalog
from .tester import run

console = Console()


def _banner() -> None:
    console.print(f"[bold red]{SPIKE_BANNER}[/bold red]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD prompt injection battery — глубокая панель инъекций."""


@main.command("payloads")
def payloads_cmd() -> None:
    for группа, категории in catalog().items():
        for категория, техники in категории.items():
            table = Table(title=f"{группа} / {категория} ({len(техники)})")
            table.add_column("техника")
            for t in техники:
                table.add_row(t[:90])
            console.print(table)


@main.command("add")
@click.argument("path", type=click.Path(exists=True))
def add_cmd(path: str) -> None:
    n = add_custom_payloads(path)
    console.print(f"добавлено техник: {n}")


@main.command("test")
@click.argument("url")
@click.option("--format", "fmt", default="custom",
              type=click.Choice(["custom", "openai", "get"]), show_default=True)
@click.option("--body", default=None, help="шаблон тела для custom (PAYLOAD подставляется)")
@click.option("--key", default=None, help="Bearer-ключ, если эндпоинт требует")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находки (контракт пайплайна)")
def test_cmd(url: str, fmt: str, body: str | None, key: str | None, as_json: str | None) -> None:
    """Прогнать батарею инъекций по эндпоинту."""
    d = run(url, fmt=fmt, body=body, key=key)
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")

    # 🔴 rc=2 «не состоялась» ≠ rc=0 «чисто»
    if d["verdict"] == "НЕ ПРОВЕРЕНО":
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {d['not_proven']}")
        raise SystemExit(2)

    if d["findings"]:
        table = Table(title=f"spike: {url}  ·  техник: {d['techniques_total']}")
        table.add_column("вердикт"); table.add_column("группа/категория"); table.add_column("техника")
        for f in d["findings"][:40]:
            цвет = "red" if f["вердикт"] == "ПРОВАЛ" else "yellow"
            table.add_row(f"[{цвет}]{f['вердикт']}[/{цвет}]",
                          f"{f['группа']}/{f['категория']}", f.get("техника", f.get("почему", "")))
        console.print(table)
    цвет = {"ПРОВАЛ": "red", "ВНИМАНИЕ": "yellow"}.get(d["verdict"], "green")
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")
    console.print(f"[dim]{d['note']}[/dim]")

    if d["verdict"] == "ПРОВАЛ":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
