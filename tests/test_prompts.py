from __future__ import annotations

import unittest

from harness.prompts import PromptError, load_prompt, prompt_variables


class PromptTemplateTests(unittest.TestCase):
    def test_agent_task_variables(self) -> None:
        self.assertEqual(prompt_variables("agent_task"),
                         {"region", "task", "policy_section", "mcp_server_name", "tools", "modality_section"})

    def test_missing_variable_is_an_error(self) -> None:
        with self.assertRaisesRegex(PromptError, "policy_section"):
            load_prompt("agent_task", region="r", task="t", mcp_server_name="m", tools="x", modality_section="y")

    def test_render(self) -> None:
        text = load_prompt("agent_task", region="us-east-1", task="Add a subnet.", policy_section="",
                           mcp_server_name="cloudgym", tools="`finish`",
                           modality_section=load_prompt("modality_hybrid").strip())
        self.assertIn("Work only in region us-east-1.", text)
        self.assertIn("## Task\nAdd a subnet.\n\n## Tools", text)
        self.assertNotIn("## Policy", text)
        self.assertIn("the `aws` CLI,\nPython (boto3), or Terraform", text)

    def test_unknown_template(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_prompt("nope")


if __name__ == "__main__":
    unittest.main()
