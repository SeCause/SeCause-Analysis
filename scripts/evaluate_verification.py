"""Run labeled synthetic cases against Claude and save results for human review."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.schemas.verification import VerificationRequest
from app.services.verification.service import verify_answer


def label_match(result, expected):
    """Compare per-field verdict counts; this does not measure semantic fidelity."""
    return all(
        Counter(item.verdict.value for item in result.results if item.field.value == field)
        == Counter(labels)
        for field, labels in expected.items()
    )


def main():
    """Validate fixtures offline or run the model and export inspectable results."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=Path(__file__).resolve().parents[1] / 'verification_eval/cases.json')
    parser.add_argument('--output', type=Path, default=Path('verification-evaluation.json'))
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--input-usd-per-million', type=float)
    parser.add_argument('--output-usd-per-million', type=float)
    args = parser.parse_args()
    rates = (args.input_usd_per_million, args.output_usd_per_million)
    if (rates[0] is None) != (rates[1] is None) or any(rate is not None and rate < 0 for rate in rates):
        parser.error('Supply both nonnegative token prices, or neither.')
    cases = json.loads(args.dataset.read_text())
    if not cases:
        parser.error('Dataset must not be empty.')
    for case in cases:
        VerificationRequest.model_validate(case['request'])
        assert set(case['expected']) == {'summary', 'rootCause', 'impact'}
        assert all(labels and set(labels) <= {'SUPPORTED', 'CONTRADICTED', 'INSUFFICIENT_EVIDENCE'} for labels in case['expected'].values())
    if args.validate_only:
        print(f'Validated {len(cases)} cases; no model calls made.')
        return
    rows = []
    for case in cases:
        row = {'id': case['id'], 'expected': case['expected'], 'review_focus': case['review_focus']}
        try:
            result = verify_answer(VerificationRequest.model_validate(case['request']))
            row.update(result=result.model_dump(mode='json', by_alias=True), label_match=label_match(result, case['expected']))
            row['estimated_cost_usd'] = None if rates[0] is None else (
                result.usage.input_tokens * rates[0] + result.usage.output_tokens * rates[1]
            ) / 1_000_000
        except Exception as exc:
            # Do not export SDK exception bodies or credentials.
            row.update(error=type(exc).__name__, label_match=False)
        rows.append(row)
        print(f"{case['id']}: {'error' if 'error' in row else 'completed'}", flush=True)
    report = {
        'created_at': datetime.now(timezone.utc).isoformat(),
        'note': 'Label match is a proxy. Human review of claim completeness and entailment is required. Failed calls may incur unreported token costs.',
        'label_match_rate': sum(row['label_match'] for row in rows) / len(rows),
        'errors': sum('error' in row for row in rows),
        'token_prices_usd_per_million': {'input': rates[0], 'output': rates[1]},
        'cases': rows,
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(f"Saved {len(rows)} cases ({report['errors']} errors) to {args.output}")
    if report['errors']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
