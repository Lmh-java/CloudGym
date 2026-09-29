import unittest

from harness.pricing import OPENAI_RATES, agent_cost_usd, codex_cost_usd, rates_for


class PricingTest(unittest.TestCase):
    def test_codex_cost_splits_cached_from_uncached_and_bills_reasoning_once(self) -> None:
        usage = {"input_tokens": 98_269, "cached_input_tokens": 89_728, "cache_write_input_tokens": 0,
                 "output_tokens": 1_692, "reasoning_output_tokens": 465}
        r = OPENAI_RATES["gpt-5.5"]
        expected = (8_541 * r.input + 89_728 * r.cached_input + 1_692 * r.output) / 1e6
        self.assertAlmostEqual(codex_cost_usd("gpt-5.5", usage), expected, places=6)

    def test_cache_writes_carry_the_multiplier(self) -> None:
        usage = {"input_tokens": 1_000_000, "cached_input_tokens": 0, "cache_write_input_tokens": 1_000_000,
                 "output_tokens": 0}
        r = OPENAI_RATES["gpt-5.6-sol"]
        self.assertAlmostEqual(codex_cost_usd("gpt-5.6-sol", usage), r.input * r.cache_write_multiplier, places=6)

    def test_unknown_model_or_empty_usage_is_none(self) -> None:
        self.assertIsNone(codex_cost_usd("gpt-9", {"input_tokens": 5}))
        self.assertIsNone(codex_cost_usd("gpt-5.5", {}))
        self.assertIsNone(codex_cost_usd("gpt-5.5", {"input_tokens": 0, "output_tokens": 0}))

    def test_dated_model_id_resolves(self) -> None:
        self.assertIs(rates_for("GPT-5.6-sol-2026-08-01"), OPENAI_RATES["gpt-5.6-sol"])
        self.assertIsNone(rates_for("claude-opus-5"))

    def test_agent_block_prefers_the_cli_figure_and_estimates_only_codex(self) -> None:
        self.assertEqual(agent_cost_usd({"provider": "codex", "cost_usd": 0.5, "model": "gpt-5.5",
                                         "usage": {"input_tokens": 10, "output_tokens": 10}}), 0.5)
        est = agent_cost_usd({"provider": "codex", "cost_usd": None, "model": "gpt-5.5",
                              "usage": {"input_tokens": 1_000_000, "cached_input_tokens": 0, "output_tokens": 0}})
        self.assertAlmostEqual(est, OPENAI_RATES["gpt-5.5"].input)
        self.assertIsNone(agent_cost_usd({"provider": "claude", "cost_usd": None, "model": "claude-opus-5",
                                          "usage": {"input_tokens": 1_000_000}}))
        self.assertIsNone(agent_cost_usd(None))


if __name__ == "__main__":
    unittest.main()
