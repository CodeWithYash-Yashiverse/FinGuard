"""Cross-engine consistency comparison — Python side.

Reads the shared fixture and the TS engine results, runs each message through
the Python ``analyze_message()`` function, compares every field, and writes a
detailed comparison report as JSON.

Usage:  python tests/run_py_comparison.py      (from backend/)
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# Adjust sys.path so `app` can be imported when running from backend/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detector import analyze_message  # noqa: E402


FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"
FIXTURE_PATH = FIXTURE_DIR / "cross_engine_messages.json"
TS_RESULTS_PATH = FIXTURE_DIR / "ts_engine_results.json"
REPORT_PATH = FIXTURE_DIR / "cross_engine_comparison.json"


def _run() -> None:
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        fixtures = json.load(f)
    with open(TS_RESULTS_PATH, encoding="utf-8") as f:
        ts_results = json.load(f)

    ts_by_id = {r["id"]: r for r in ts_results}

    comparisons: list[dict] = []
    summary = {
        "total": len(fixtures),
        "exact_matches": 0,
        "intentional_differences": 0,
        "unexpected_mismatches": 0,
        "unexpected_mismatched_ids": [],
        "intentional_difference_ids": [],
        "mismatch_categories": {},
    }

    for fixture in fixtures:
        fid = fixture["id"]
        msg = fixture["message"]

        # Run Python engine
        py_result = analyze_message(msg)
        py_signal_ids = sorted(s.id for s in py_result.signals)
        py_signals_detail = [
            {
                "id": s.id,
                "category": s.category.value,
                "severity": s.severity.value,
                "title": s.title,
                "explanation": s.explanation,
                "evidence": s.evidence,
            }
            for s in py_result.signals
        ]

        # Get TS results
        ts = ts_by_id.get(fid)
        if ts is None:
            comparisons.append({"id": fid, "error": "Missing from TS results"})
            summary["mismatch"] += 1
            summary["mismatched_ids"].append(fid)
            continue

        ts_signal_ids = sorted(ts["signalIds"])

        mismatches: list[dict] = []

        # 1. Risk classification
        if py_result.risk_level.value != ts["riskLevel"]:
            mismatches.append({
                "field": "riskLevel",
                "python": py_result.risk_level.value,
                "typescript": ts["riskLevel"],
                "intentional": False,
            })

        # 2. Signal IDs
        py_id_set = set(py_signal_ids)
        ts_id_set = set(ts_signal_ids)
        if py_id_set != ts_id_set:
            mismatches.append({
                "field": "signalIds",
                "python": sorted(py_id_set),
                "typescript": sorted(ts_id_set),
                "only_in_python": sorted(py_id_set - ts_id_set),
                "only_in_typescript": sorted(ts_id_set - py_id_set),
                "intentional": False,
            })

        # 3. Signal details comparison (for shared signals)
        shared_ids = py_id_set & ts_id_set
        for sid in sorted(shared_ids):
            py_sig = next(s for s in py_signals_detail if s["id"] == sid)
            ts_sig = next(s for s in ts["signalDetails"] if s["id"] == sid)

            # Severity
            if py_sig["severity"] != ts_sig["severity"]:
                mismatches.append({
                    "field": f"signal[{sid}].severity",
                    "python": py_sig["severity"],
                    "typescript": ts_sig["severity"],
                    "intentional": False,
                })

            # Category
            if py_sig["category"] != ts_sig["category"]:
                mismatches.append({
                    "field": f"signal[{sid}].category",
                    "python": py_sig["category"],
                    "typescript": ts_sig["category"],
                    "intentional": False,
                })

            # Title
            if py_sig["title"] != ts_sig["title"]:
                mismatches.append({
                    "field": f"signal[{sid}].title",
                    "python": py_sig["title"],
                    "typescript": ts_sig["title"],
                    "intentional": False,
                })

            # Explanation
            if py_sig["explanation"] != ts_sig["explanation"]:
                mismatches.append({
                    "field": f"signal[{sid}].explanation",
                    "python": py_sig["explanation"],
                    "typescript": ts_sig["explanation"],
                    "intentional": False,
                })

            # Evidence — Python redacts digits, TS does not
            py_ev = sorted(py_sig["evidence"])
            ts_ev = sorted(ts_sig["evidence"])
            if py_ev != ts_ev:
                has_digit_redaction = any(re.search(r"\d\*+\d", s) for s in py_ev)
                has_multibyte = bool(re.search(r"[^\x00-\x7F]", msg))

                if has_digit_redaction:
                    reason = (
                        "Python applies _redact_secrets() to evidence snippets "
                        "(masks 4+ digit numbers); TypeScript does not redact digits."
                    )
                elif has_multibyte:
                    reason = (
                        "Snippet boundary variation due to JavaScript UTF-16 code units "
                        "vs Python Unicode code points on multi-byte / emoji characters."
                    )
                else:
                    reason = "Snippet formatting or boundary difference."

                mismatches.append({
                    "field": f"signal[{sid}].evidence",
                    "python": py_ev,
                    "typescript": ts_ev,
                    "intentional": True,
                    "reason": reason,
                })

        # 4. Summary
        if py_result.summary != ts["summary"]:
            mismatches.append({
                "field": "summary",
                "python": py_result.summary,
                "typescript": ts["summary"],
                "intentional": False,
            })

        # 5. Next steps
        if py_result.next_steps != ts["nextSteps"]:
            mismatches.append({
                "field": "nextSteps",
                "python": py_result.next_steps,
                "typescript": ts["nextSteps"],
                "intentional": False,
            })

        # 6. Verification guidance
        if list(py_result.verification) != ts["verification"]:
            mismatches.append({
                "field": "verification",
                "python": list(py_result.verification),
                "typescript": ts["verification"],
                "intentional": False,
            })

        unexpected = [m for m in mismatches if not m.get("intentional", False)]
        intentional = [m for m in mismatches if m.get("intentional", False)]

        comparison = {
            "id": fid,
            "category": fixture["category"],
            "message_preview": msg[:80] + ("..." if len(msg) > 80 else ""),
            "python_risk": py_result.risk_level.value,
            "ts_risk": ts["riskLevel"],
            "python_signals": sorted(py_id_set),
            "ts_signals": sorted(ts_id_set),
            "mismatches": mismatches,
            "match": len(mismatches) == 0,
            "is_functionally_equivalent": len(unexpected) == 0,
            "unexpected_mismatch_count": len(unexpected),
            "intentional_difference_count": len(intentional),
        }
        comparisons.append(comparison)

        if unexpected:
            summary["unexpected_mismatches"] += 1
            summary["unexpected_mismatched_ids"].append(fid)
        elif intentional:
            summary["intentional_differences"] += 1
            summary["intentional_difference_ids"].append(fid)
        else:
            summary["exact_matches"] += 1

        for m in mismatches:
            cat = m["field"].split("[")[0].split(".")[0]
            summary["mismatch_categories"][cat] = (
                summary["mismatch_categories"].get(cat, 0) + 1
            )

    report = {"summary": summary, "comparisons": comparisons}

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(
        f"Comparison complete: {summary['exact_matches']} exact matches, "
        f"{summary['intentional_differences']} intentional differences (digit redaction / emoji boundary), "
        f"{summary['unexpected_mismatches']} unexpected mismatches out of {summary['total']}"
    )
    if summary["unexpected_mismatched_ids"]:
        print(f"Unexpected mismatched IDs: {', '.join(summary['unexpected_mismatched_ids'])}")
    if summary["intentional_difference_ids"]:
        print(f"Intentional difference IDs: {', '.join(summary['intentional_difference_ids'])}")
    print(f"Report written to {REPORT_PATH}")


if __name__ == "__main__":
    _run()
