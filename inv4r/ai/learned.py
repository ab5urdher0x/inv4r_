"""Lane 1 — learned proposer: a real trained model, fully offline."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

_TOKEN_RE = re.compile(r"[a-zA-Z_]+|\d+|[^\w\s]")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_NUM_RE = re.compile(r"\d+")


def normalize_text(text: str) -> str:
    """Collapse values that must not distinguish two otherwise-identical lines.

    An approved ``ntp server 10.50.0.10`` must generalize to
    ``ntp server 10.50.0.11``; without this the IP octets and numbers would be
    treated as distinguishing tokens and the learned lane would never fire.
    """
    text = _IPV4_RE.sub(" ipv4addr ", text or "")
    return _NUM_RE.sub(" num ", text)


def tokenize(path: str, value: str = "") -> list[str]:
    """Lexical tokens from a raw path + value. Dotted segments are split so"""
    text = normalize_text(f"{path.replace('.', ' . ')} {value}")
    return [t.lower() for t in _TOKEN_RE.findall(text)]


def _example_key(path: str, value: str, fact: str) -> tuple[str, str, str]:
    """Identity of a training example, insensitive to punctuation and spacing.

    The same approval arrives from two places — the decision ledger (the raw
    line) and the ACTIVE pack it produced (a path_regex rendered as text) — so a
    plain string comparison would learn that line twice and weight it above
    every other one.
    """
    def norm(text: str) -> str:
        return " ".join(re.sub(r"[^\w\s]+", " ", str(text).lower()).split())

    return (norm(path), norm(value), str(fact).strip().lower())


@dataclass
class Neighbor:
    fact: str
    similarity: float
    example_path: str


@dataclass
class LearnedModel:
    """Tiny TF-IDF + k-NN classifier over configuration language."""

    min_confidence: float = 0.45
    top_k: int = 5
    _docs: list[tuple[list[str], str, str]] = field(default_factory=list)
    _df: Counter = field(default_factory=Counter)
    _idf: dict[str, float] = field(default_factory=dict)
    _vectors: list[tuple[dict[str, float], str, str]] = field(default_factory=list)


    def fit(self, examples: list[tuple[str, str, str]]) -> "LearnedModel":
        """examples: (path, value, canonical_fact) — one per approved rule.

        Identical examples are collapsed: one approval is recorded both in the
        decision ledger and in the mapping pack it activates, and learning it
        twice would weight that line above every other one.
        """
        self._docs = []
        seen: set[tuple[str, str, str]] = set()
        for path, value, fact in examples:
            key = _example_key(path, value, fact)
            if key in seen:
                continue
            seen.add(key)
            toks = tokenize(path, value)
            if toks:
                self._docs.append((toks, fact, path))
        self._rebuild()
        return self

    def _rebuild(self) -> None:
        n = max(len(self._docs), 1)
        self._df = Counter()
        for toks, _, _ in self._docs:
            self._df.update(set(toks))
        self._idf = {t: math.log((1 + n) / (1 + df)) + 1.0 for t, df in self._df.items()}
        self._vectors = [(self._vec(toks), fact, path) for toks, fact, path in self._docs]

    def _vec(self, toks: list[str]) -> dict[str, float]:
        tf = Counter(toks)
        norm = math.sqrt(sum((1 + math.log(c)) * self._idf.get(t, 1.0) ** 2
                             for t, c in tf.items())) or 1.0
        return {t: (1 + math.log(c)) * self._idf.get(t, 1.0) / norm for t, c in tf.items()}


    @staticmethod
    def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
        if len(b) < len(a):
            a, b = b, a
        return sum(v * b.get(t, 0.0) for t, v in a.items())

    def neighbors(self, path: str, value: str = "") -> list[Neighbor]:
        if not self._vectors:
            return []
        q = self._vec(tokenize(path, value))
        scored = [(self._cosine(q, v), fact, ex) for v, fact, ex in self._vectors]
        scored.sort(key=lambda x: -x[0])
        return [Neighbor(fact=f, similarity=s, example_path=p)
                for s, f, p in scored[: self.top_k] if s > 0]

    def propose(self, path: str, value: str = "") -> tuple[str, float, dict[str, Any]] | None:
        """Returns (fact, confidence, explanation) or None."""
        neigh = self.neighbors(path, value)
        if not neigh:
            return None
        votes: dict[str, float] = {}
        for nb in neigh:
            votes[nb.fact] = votes.get(nb.fact, 0.0) + nb.similarity
        total = sum(votes.values()) or 1.0
        best_fact = max(votes, key=votes.get)
        agreement = votes[best_fact] / total
        top_sim = neigh[0].similarity
        confidence = round(min(1.0, max(0.0, agreement * 0.6 + top_sim * 0.4)), 3)
        if confidence < self.min_confidence:
            return None
        return best_fact, confidence, {
            "model": "tfidf-knn",
            "trained_examples": len(self._docs),
            "top_similarity": round(top_sim, 3),
            "neighbors": [{"fact": nb.fact, "sim": round(nb.similarity, 3),
                           "example": nb.example_path} for nb in neigh[:3]],
        }

    def trained_on(self) -> int:
        return len(self._docs)


def examples_from_decisions(mappings_dir) -> list[tuple[str, str, str]]:
    """Training examples from APPROVED review-queue decisions.

    Review approvals are the durable record the operator actually produces; the
    learned lane must read them, or approving a mapping teaches the system
    nothing (the reported bug).
    """
    from inv4r.core.facts import CANONICAL_FACTS
    from inv4r.training.queue import load_fragment_decisions

    out: list[tuple[str, str, str]] = []
    for rec in load_fragment_decisions(mappings_dir).values():
        if str(rec.get("decision", "")).upper() != "APPROVED":
            continue
        fact = rec.get("fact")
        if fact not in CANONICAL_FACTS:
            continue
        raw = str(rec.get("raw_text") or "").strip()
        if raw:
            out.append((raw, raw, fact))
    return out


def examples_from_registry(registry) -> list[tuple[str, str, str]]:
    """Extract training examples from ACTIVE mapping packs only."""
    from inv4r.mapping.registry import PackStatus

    examples: list[tuple[str, str, str]] = []
    for pack in registry.packs:
        if getattr(pack, "status", PackStatus.ACTIVE) != PackStatus.ACTIVE:
            continue
        for rule in pack.rules:
            # Runtime-approved rules carry the original raw line in their notes
            # ("evidence: <line> | from training session …"); prefer it so the
            # pack example and its decision-ledger twin deduplicate to one.
            match = re.search(r"evidence: (.*?) \| from training session", rule.notes or "")
            if match:
                raw = match.group(1).strip()
                value_hint = raw
            else:
                raw = rule.path_regex.strip("^$").replace("\\.", ".").replace("\\-", "-")
                raw = raw.replace("\\d", "0").replace("\\", "")
                value_hint = ""
                if rule.value_regex:
                    value_hint = rule.value_regex.strip("^$()\\b").replace("|", " ")
            examples.append((raw, value_hint, rule.fact))
    return examples
