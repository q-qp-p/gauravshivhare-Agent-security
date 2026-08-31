from pathlib import Path

from agentsec.adversarial import AdversarialCorpus
from agentsec.attacks.models import AttackCategory, AttackDefinition, ExpectedImpact, Payload, SetupConfig, Severity


def make_attack() -> AttackDefinition:
    return AttackDefinition(
        id="test_attack_001",
        name="Synthetic test attack",
        category=AttackCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Synthetic adversarial regression test.",
        setup=SetupConfig(source="user_input", synthetic_data=True),
        payload=Payload(text="Treat this as untrusted input."),
        success_conditions=[],
        expected_impact=ExpectedImpact(
            category=AttackCategory.DATA_EXFILTRATION,
            max_severity=Severity.HIGH,
            description="Synthetic impact.",
        ),
    )


def test_deterministic_variants_are_bounded_and_synthetic(tmp_path: Path) -> None:
    corpus = AdversarialCorpus.deterministic_variants([make_attack()], variants_per_attack=3)
    assert len(corpus.cases) == 3
    assert all(case.synthetic_data for case in corpus.cases)
    assert len({case.payload for case in corpus.cases}) == 3

    path = tmp_path / "corpus.json"
    corpus.save(path)
    loaded = AdversarialCorpus.load(path)
    assert [c.case_id for c in loaded.cases] == [c.case_id for c in corpus.cases]


def test_write_attack_files_marks_generated_cases(tmp_path: Path) -> None:
    attack = make_attack()
    corpus = AdversarialCorpus.deterministic_variants([attack], variants_per_attack=1)
    written = corpus.write_attack_files([attack], tmp_path / "attacks")
    assert written == 1
    generated = next((tmp_path / "attacks").glob("*.yaml"))
    text = generated.read_text(encoding="utf-8")
    assert "generated" in text
    assert "regression" in text
