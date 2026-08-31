"""CLI for generating and inspecting the AgentSec adversarial corpus."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from agentsec.adversarial import AdversarialCorpus
from agentsec.attacks.registry import AttackLoader

console = Console()


@click.group()
def main() -> None:
    """Generate synthetic adversarial variants for AgentSec regression testing."""


@main.command("generate")
@click.option("--attacks-dir", default="attacks", show_default=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output", default="tests/corpus/adversarial.json", show_default=True, type=click.Path(path_type=Path))
@click.option("--variants", default=2, show_default=True, type=click.IntRange(1, 10))
def generate(attacks_dir: Path, output: Path, variants: int) -> None:
    """Generate deterministic, synthetic adversarial regression cases."""
    attacks = AttackLoader.load_directory(attacks_dir)
    if not attacks:
        raise click.ClickException(f"No attacks found in {attacks_dir}")
    corpus = AdversarialCorpus.deterministic_variants(attacks, variants)
    corpus.save(output)
    console.print(f"[green]✓[/green] Generated {len(corpus.cases)} cases → {output}")


@main.command("check")
@click.option("--corpus", default="tests/corpus/adversarial.json", show_default=True, type=click.Path(exists=True, path_type=Path))
def check(corpus: Path) -> None:
    """Validate that a committed corpus is well-formed and synthetic."""
    loaded = AdversarialCorpus.load(corpus)
    if not loaded.cases:
        raise click.ClickException("Corpus is empty")
    bad = [c.case_id for c in loaded.cases if not c.synthetic_data or not c.payload.strip()]
    if bad:
        raise click.ClickException(f"Invalid/non-synthetic cases: {', '.join(bad[:10])}")
    console.print(f"[green]✓[/green] Corpus valid: {len(loaded.cases)} synthetic cases")


@main.command("stats")
@click.option("--corpus", default="tests/corpus/adversarial.json", show_default=True, type=click.Path(exists=True, path_type=Path))
def stats(corpus: Path) -> None:
    """Print category/severity counts for a corpus."""
    loaded = AdversarialCorpus.load(corpus)
    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    for case in loaded.cases:
        categories[case.category] = categories.get(case.category, 0) + 1
        severities[case.severity] = severities.get(case.severity, 0) + 1
    console.print(json.dumps({"total": len(loaded.cases), "categories": categories, "severities": severities}, indent=2))


if __name__ == "__main__":
    main()
