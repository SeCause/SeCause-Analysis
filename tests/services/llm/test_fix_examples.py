import json
import unittest
from unittest.mock import patch

from app.schemas.explanation import ExplanationResult, FixExample
from app.schemas.finding import Finding
from app.services.callback.spring_client import AnalysisSuccessCallbackPayload, AnalysisSummary
from app.services.llm.claude_client import (
    ClaudeClientError, EXPLANATION_TOOL_SCHEMA, _build_explanation_result,
    parse_explanation_response,
)
from app.services.llm.explanation_generator import (
    ensure_fix_examples, enrich_finding_with_explanation,
)
from app.services.llm.prompt_builder import build_explanation_prompt


def finding(path="src/main.py", kind="SQL_INJECTION"):
    return Finding(tool="SEMGREP", type=kind, cwe_id="CWE-89", severity="HIGH",
                   file_path=path, line_start=1, message="취약점 발견", evidence="unsafe()")


def example(code, language=None):
    return FixExample(language=language, fixed_code=code, explanation="입력값을 분리합니다.")


def payload(examples):
    return dict(summary="요약", rootCause="원인", impact="영향", recommendation="매개변수화 쿼리를 사용하세요.",
                fixExamples=examples)


class FixExamplesTest(unittest.TestCase):
    def test_normal_code_including_korean_comments_and_literals(self):
        cases = [
            ("x.py", '# 한글 주석\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'),
            ("x.java", '// 한글 주석\nPreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, "사용자");'),
            ("x.js", '// 한글 주석\nconst label = "사용자"\ndb.query("SELECT * FROM users WHERE id=$1", [userId])'),
            ("x.ts", 'const name: string = "사용자";\ndb.query(query, [name]);'),
            ("x.tsx", 'const view = <div>사용자</div>;'),
            ("x.yaml", '# 한글 주석\nsecurityContext:\n  runAsNonRoot: true\n  label: 사용자'),
            ("x.json", '{"label": "사용자", "secure": true}'),
        ]
        for path, code in cases:
            with self.subTest(path=path):
                result = ensure_fix_examples(finding(path), [example(code)])
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0].fixed_code, code)

    def test_prose_empty_and_comments_are_omitted(self):
        for path in ["x.py", "x.java", "x.js", "x.ts", "x.yaml", "x.json"]:
            for code in ["", "  ", "취약한 API 사용을 안전한 API로 교체해야 합니다.",
                         "Use parameterized queries;", "PreparedStatement", "안내", '"설명"']:
                with self.subTest(path=path, code=code):
                    self.assertEqual(ensure_fix_examples(finding(path), [example(code)]), [])
        for path, code in [("x.py", "# 안내"), ("x.java", "// 안내"), ("x.js", "// 안내"), ("x.yaml", "# 안내")]:
            self.assertEqual(ensure_fix_examples(finding(path), [example(code)]), [])

    def test_complete_fence_is_unwrapped_but_mixed_prose_is_omitted(self):
        result = ensure_fix_examples(finding(), [example('```python\ncursor.execute(query, (user_id,))\n```')])
        self.assertEqual(result[0].fixed_code, 'cursor.execute(query, (user_id,))')
        for code in ['설명입니다.\n```python\nsafe()\n```', '```java\nsafe()\n```', 'safe()\n수정해야 합니다.']:
            self.assertEqual(ensure_fix_examples(finding(), [example(code)]), [])

    def test_nested_prose_and_invalid_syntax_are_omitted(self):
        cases = [
            ("x.py", "def fix():\n    safe()\n    안내"),
            ("x.js", "function fix() { safe(); 안내; }"),
            ("x.java", "void fix() { safe(); 안내; }"),
            ("x.py", "cursor.execute("),
            ("x.js", "const value = ;"),
            ("x.java", "PreparedStatement stmt = ;"),
            ("x.yaml", "securityContext: ["),
        ]
        for path, code in cases:
            with self.subTest(path=path):
                self.assertEqual(ensure_fix_examples(finding(path), [example(code)]), [])

    def test_target_language_overrides_claim_and_unknown_language_is_omitted(self):
        java = 'PreparedStatement stmt = connection.prepareStatement(sql);'
        for path in ["x.py", "x.js", "x.ts", "x.yaml"]:
            self.assertEqual(ensure_fix_examples(finding(path), [example(java, "Java")]), [])
        self.assertEqual(ensure_fix_examples(finding("x.py"), [example(java, "Python")]), [])
        self.assertEqual(ensure_fix_examples(finding("x.rb"), [example('safe()', "ruby")]), [])
        self.assertEqual(ensure_fix_examples(finding(), [example('safe()', "py")])[0].language, "python")

    def test_invalid_first_example_does_not_hide_later_valid_code(self):
        result = ensure_fix_examples(finding(), [example('수정이 필요합니다.'), example('safe()')])
        self.assertEqual([item.fixed_code for item in result], ['safe()'])

    def test_vulnerable_code_is_also_code_only(self):
        item = example('safe()')
        item.vulnerable_code = '취약한 코드를 수정합니다.'
        self.assertIsNone(ensure_fix_examples(finding(), [item])[0].vulnerable_code)

    def test_both_response_parsers_discard_malformed_optional_examples(self):
        data = payload([dict(fixedCode=None), dict(fixedCode="safe()", explanation="안전")])
        for result in [_build_explanation_result(data), parse_explanation_response(json.dumps(data))]:
            self.assertEqual(result.recommendation, data['recommendation'])
            self.assertEqual(len(result.fix_examples), 1)

    def test_claude_empty_prose_and_failure_preserve_success_callback(self):
        for path in ["x.py", "x.java", "x.js", "x.yaml"]:
            for response in [ExplanationResult.model_validate(payload([])),
                             ExplanationResult.model_validate(payload([example('일반 설명입니다.').model_dump(by_alias=True)])),
                             ClaudeClientError('mock failure')]:
                with self.subTest(path=path, response=type(response).__name__):
                    with patch('app.services.llm.explanation_generator.ClaudeExplanationClient') as client:
                        if isinstance(response, Exception):
                            client.return_value.generate_explanation.side_effect = response
                        else:
                            client.return_value.generate_explanation.return_value = response
                        enriched = enrich_finding_with_explanation(finding(path), [])
                    body = AnalysisSuccessCallbackPayload(analysis_id=1, repository_id=2,
                        findings=[enriched], summary=AnalysisSummary(total_count=1)).model_dump(by_alias=True, mode='json')
                    self.assertEqual(body['status'], 'COMPLETED')
                    self.assertEqual(body['findings'][0]['fixExamples'], [])
                    self.assertTrue(body['findings'][0]['recommendation'])
                    self.assertTrue(body['findings'][0]['summary'])

    def test_non_sqli_fallback_has_no_fake_code(self):
        with patch('app.services.llm.explanation_generator.ClaudeExplanationClient', side_effect=ClaudeClientError('mock')):
            result = enrich_finding_with_explanation(finding(kind='XSS'), [])
        self.assertEqual(result.fix_examples, [])
        self.assertTrue(result.recommendation)

    def test_normal_claude_response_reaches_callback_with_code(self):
        response = ExplanationResult.model_validate(payload([example('safe()').model_dump(by_alias=True)]))
        with patch('app.services.llm.explanation_generator.ClaudeExplanationClient') as client:
            client.return_value.generate_explanation.return_value = response
            result = enrich_finding_with_explanation(finding(), [])
        self.assertEqual(result.model_dump(by_alias=True)['fixExamples'][0]['fixedCode'], 'safe()')

    def test_prompt_and_tool_contract_allow_empty_examples(self):
        prompt = build_explanation_prompt(finding(), [])
        self.assertIn('Target language: python', prompt)
        self.assertIn('fixExamples: []', prompt)
        self.assertIn('Markdown fences or prose', prompt)
        schema = EXPLANATION_TOOL_SCHEMA['input_schema']['properties']['fixExamples']
        self.assertEqual(schema['minItems'], 0)


if __name__ == '__main__':
    unittest.main()
