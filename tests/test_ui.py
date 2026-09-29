"""Tests for UI display functions and the interactive prompt filter."""

import re
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from rich.text import Text

from dropkit.ui import (
    EditablePrompt,
    FilterError,
    _filterable_fields,
    _readline_prompt,
    apply_filter,
    parse_filter,
    prompt_with_help,
)

# Trimmed real /v2/sizes objects, enough to exercise every filterable field
SIZES = [
    {
        "slug": "s-1vcpu-1gb",
        "vcpus": 1,
        "memory": 1024,
        "disk": 25,
        "transfer": 1.0,
        "price_monthly": 6.0,
        "description": "Basic",
    },
    {
        "slug": "s-4vcpu-8gb",
        "vcpus": 4,
        "memory": 8192,
        "disk": 160,
        "transfer": 5.0,
        "price_monthly": 48.0,
        "description": "Basic",
    },
    {
        "slug": "g-4vcpu-16gb",
        "vcpus": 4,
        "memory": 16384,
        "disk": 50,
        "transfer": 5.0,
        "price_monthly": 126.0,
        "description": "General Purpose",
    },
    {
        "slug": "so-2vcpu-16gb",
        "vcpus": 2,
        "memory": 16384,
        "disk": 300,
        "transfer": 4.0,
        "price_monthly": 131.0,
        "description": "Storage-Optimized",
    },
]


class TestParseFilterFields:
    """Tests for field names in parse_filter."""

    def test_cpu_maps_to_vcpus(self):
        """Test 'cpu' maps to the API's 'vcpus' key."""
        assert parse_filter("cpu>=4") == [("vcpus", ">=", 4.0)]

    def test_mem_maps_to_memory(self):
        """Test 'mem' maps to the API's 'memory' key."""
        assert parse_filter("mem>=16") == [("memory", ">=", 16384.0)]

    @pytest.mark.parametrize("spelling", ["vcpus", "vcpu", "cpus", "memory", "ram"])
    def test_only_the_advertised_spelling_is_accepted(self, spelling):
        """Test one name per field, so the footer lists exactly what parses."""
        with pytest.raises(FilterError, match="unknown field"):
            parse_filter(f"{spelling}>=4")

    def test_price_maps_to_price_monthly(self):
        """Test 'price' maps to the API's 'price_monthly' key."""
        assert parse_filter("price<=150") == [("price_monthly", "<=", 150.0)]

    def test_field_is_case_insensitive(self):
        """Test uppercase field names are accepted."""
        assert parse_filter("CPU>=4") == [("vcpus", ">=", 4.0)]


class TestParseFilterOperators:
    """Tests for operator handling in parse_filter."""

    @pytest.mark.parametrize("op", [">=", "<=", ">", "<", "="])
    def test_each_operator(self, op):
        """Test every supported operator parses."""
        assert parse_filter(f"cpu{op}4") == [("vcpus", op, 4.0)]

    def test_two_char_operator_not_split(self):
        """Test '>=' parses as one operator, not '>' plus a stray '='."""
        assert parse_filter("cpu>=4") == [("vcpus", ">=", 4.0)]

    def test_spaces_around_operator(self):
        """Test whitespace around the operator is tolerated."""
        assert parse_filter("mem >= 16") == [("memory", ">=", 16384.0)]


class TestParseFilterValues:
    """Tests for value and unit handling in parse_filter."""

    @pytest.mark.parametrize("value", [0.5, 16, 1023, 1024, 1025, 16384])
    def test_bare_memory_is_always_gb(self, value):
        assert parse_filter(f"mem>={value}") == [("memory", ">=", value * 1024)]
        assert parse_filter(f"mem>={value}") == parse_filter(f"mem>={value}gb")

    def test_gb_and_mb_suffixes_agree(self):
        """Test the explicit suffixes both land on the same MB value."""
        assert parse_filter("mem>=16gb") == parse_filter("mem>=16384mb")

    def test_memory_tb_suffix(self):
        """Test a TB memory suffix converts to MB."""
        assert parse_filter("mem>=1tb") == [("memory", ">=", 1024.0 * 1024)]

    def test_disk_tb_suffix_converts_to_gb(self):
        """Test disk is reported in GB so a TB suffix scales up."""
        assert parse_filter("disk>=1tb") == [("disk", ">=", 1024.0)]

    def test_disk_bare_number_is_gb(self):
        """Test a bare disk number is already in the API's unit."""
        assert parse_filter("disk>=200") == [("disk", ">=", 200.0)]

    def test_transfer_tb_suffix(self):
        """Test transfer is reported in TB so a TB suffix is a no-op."""
        assert parse_filter("transfer>=5tb") == [("transfer", ">=", 5.0)]

    def test_dollar_sign_rejected(self):
        """Test '$' is not accepted; prices are bare numbers."""
        with pytest.raises(FilterError, match="not a number"):
            parse_filter("price<=$150")

    def test_decimal_value(self):
        """Test a fractional value parses."""
        assert parse_filter("price<=10.50") == [("price_monthly", "<=", 10.5)]

    def test_single_letter_unit_rejected(self):
        """Test only the full 'gb'/'mb'/'tb' suffixes are accepted."""
        with pytest.raises(FilterError, match="invalid unit"):
            parse_filter("mem>=16g")


class TestParseFilterMultipleTerms:
    """Tests for combining terms in parse_filter."""

    def test_two_terms(self):
        """Test two whitespace-separated terms both parse."""
        assert parse_filter("cpu>=4 mem>=16") == [
            ("vcpus", ">=", 4.0),
            ("memory", ">=", 16384.0),
        ]

    def test_three_terms_mixed_ops(self):
        """Test lower and upper bounds combine."""
        assert parse_filter("cpu>=4 mem>=16 price<=150") == [
            ("vcpus", ">=", 4.0),
            ("memory", ">=", 16384.0),
            ("price_monthly", "<=", 150.0),
        ]

    def test_extra_whitespace_between_terms(self):
        """Test runs of whitespace between terms are ignored."""
        assert parse_filter("  cpu>=4    mem>=16  ") == [
            ("vcpus", ">=", 4.0),
            ("memory", ">=", 16384.0),
        ]


class TestParseFilterErrors:
    """Tests for rejected filter expressions."""

    def test_bare_word_rejected(self):
        """Test free text is an error and is echoed back."""
        with pytest.raises(FilterError, match="intel"):
            parse_filter("intel")

    def test_bare_word_alongside_valid_term(self):
        """Test a valid term does not excuse trailing junk."""
        with pytest.raises(FilterError, match="intel"):
            parse_filter("cpu>=4 intel")

    def test_unknown_field(self):
        """Test an unknown field name is named in the error."""
        with pytest.raises(FilterError, match="unknown field 'gpus'"):
            parse_filter("gpus>=4")

    def test_missing_operator(self):
        """Test a field and value with no operator is an error."""
        with pytest.raises(FilterError, match="could not parse"):
            parse_filter("cpu 4")

    def test_non_numeric_value(self):
        """Test a non-numeric right-hand side is an error."""
        with pytest.raises(FilterError, match="not a number"):
            parse_filter("cpu>=lots")

    def test_unit_on_unitless_field(self):
        """Test a unit suffix on 'cpu' is rejected."""
        with pytest.raises(FilterError, match="invalid unit"):
            parse_filter("cpu>=4gb")

    def test_wrong_unit_for_field(self):
        """Test transfer rejects a unit it has no conversion for."""
        with pytest.raises(FilterError, match="invalid unit"):
            parse_filter("transfer>=5kb")

    def test_empty_filter(self):
        """Test an empty expression is an error."""
        with pytest.raises(FilterError, match="empty"):
            parse_filter("   ")


class TestApplyFilter:
    """Tests for apply_filter."""

    def test_single_term(self):
        """Test one term selects the matching rows."""
        matched = apply_filter(SIZES, parse_filter("cpu>=4"))
        assert [s["slug"] for s in matched] == ["s-4vcpu-8gb", "g-4vcpu-16gb"]

    def test_terms_are_anded(self):
        """Test multiple terms all have to hold."""
        matched = apply_filter(SIZES, parse_filter("cpu>=4 mem>=16"))
        assert [s["slug"] for s in matched] == ["g-4vcpu-16gb"]

    def test_upper_bound(self):
        """Test an upper bound excludes the expensive rows."""
        matched = apply_filter(SIZES, parse_filter("price<=50"))
        assert [s["slug"] for s in matched] == ["s-1vcpu-1gb", "s-4vcpu-8gb"]

    def test_equality(self):
        """Test '=' matches exactly."""
        matched = apply_filter(SIZES, parse_filter("cpu=2"))
        assert [s["slug"] for s in matched] == ["so-2vcpu-16gb"]

    def test_no_matches_returns_empty(self):
        """Test an unsatisfiable filter yields nothing."""
        assert apply_filter(SIZES, parse_filter("cpu>=999")) == []

    def test_row_missing_field_excluded(self):
        """Test rows lacking the filtered field are dropped, not kept."""
        rows = [{"slug": "nyc3", "name": "New York 3"}]
        assert apply_filter(rows, parse_filter("cpu>=1")) == []

    def test_row_with_non_numeric_field_excluded(self):
        """Test a non-numeric value for the field is dropped rather than raising."""
        rows = [{"slug": "weird", "vcpus": "four"}]
        assert apply_filter(rows, parse_filter("cpu>=1")) == []

    def test_boolean_field_excluded(self):
        """Test a bool is not treated as a number despite subclassing int."""
        rows = [{"slug": "weird", "vcpus": True}]
        assert apply_filter(rows, parse_filter("cpu>=1")) == []

    def test_original_rows_not_mutated(self):
        """Test filtering does not modify the input list."""
        before = list(SIZES)
        apply_filter(SIZES, parse_filter("cpu>=4"))
        assert before == SIZES


class TestEditablePrompt:
    """Tests for handing the prompt to readline so line editing redraws right."""

    def test_visible_text_is_preserved(self):
        """Test rendering keeps the words the user reads."""
        with patch("dropkit.ui.console", Console(force_terminal=True, width=80)):
            rendered = _readline_prompt(Text.from_markup("[cyan]Size[/cyan]: "))
        assert "Size" in rendered

    def test_every_escape_is_marked_non_printing(self):
        """Test each ANSI escape is bracketed, so readline counts it as zero-width."""
        with patch("dropkit.ui.console", Console(force_terminal=True, width=80)):
            rendered = _readline_prompt(Text.from_markup("[cyan]Size[/cyan] [bold](x)[/bold]: "))
        assert "\001" in rendered
        for match in re.finditer(r"\x1b\[", rendered):
            assert rendered[match.start() - 1] == "\001"

    def test_input_is_given_the_prompt(self):
        """Test input() receives the prompt rather than Rich printing it separately."""
        with patch("builtins.input", return_value="answer") as mock_input:
            result = EditablePrompt.get_input(MagicMock(), Text("Size: "), password=False)
        assert result == "answer"
        assert "Size" in mock_input.call_args.args[0]

    def test_password_keeps_richs_own_path(self):
        """Test passwords are not routed through input(), which would echo them."""
        with (
            patch("rich.prompt.PromptBase.get_input", return_value="secret") as base,
            patch("builtins.input") as mock_input,
        ):
            EditablePrompt.get_input(MagicMock(), Text("Token: "), password=True)
        base.assert_called_once()
        mock_input.assert_not_called()

    def test_explicit_stream_keeps_richs_own_path(self):
        """Test a provided stream is read from, not the terminal."""
        with (
            patch("rich.prompt.PromptBase.get_input", return_value="x") as base,
            patch("builtins.input") as mock_input,
        ):
            EditablePrompt.get_input(
                MagicMock(), Text("Size: "), password=False, stream=MagicMock()
            )
        base.assert_called_once()
        mock_input.assert_not_called()

    def test_without_readline_keeps_richs_own_path(self):
        """Test a platform with no readline still prompts, just without editing."""
        with (
            patch("dropkit.ui.readline", None),
            patch("rich.prompt.PromptBase.get_input", return_value="x") as base,
            patch("builtins.input") as mock_input,
        ):
            EditablePrompt.get_input(MagicMock(), Text("Size: "), password=False)
        base.assert_called_once()
        mock_input.assert_not_called()


class TestKeywordFooter:
    """Tests for the keyword reference printed under a table."""

    def _caption(self, answers, data=None):
        """Run the prompt and return the caption the table was given."""
        display = MagicMock()
        with patch("dropkit.ui.EditablePrompt.ask", side_effect=answers):
            prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES if data is None else data)
        return display.call_args.kwargs.get("caption") or ""

    def test_unfiltered_table_gets_the_keywords(self):
        """Test a bare '?' table carries the vocabulary."""
        caption = self._caption(["?", "s-1vcpu-1gb"])
        assert "filter fields:" in caption
        assert "operators:" in caption

    def test_filtered_table_gets_the_keywords(self):
        """Test the keywords are repeated under a filtered table too."""
        caption = self._caption(["? cpu>=4", "g-4vcpu-16gb"])
        assert "filter fields:" in caption
        assert "2 of 4 shown" in caption

    def test_fields_are_listed_one_spelling_each(self):
        """Test the footer names every field (spacing deliberately not asserted)."""
        caption = self._caption(["?", "s-1vcpu-1gb"])
        for field in ("mem", "cpu", "disk", "transfer", "price"):
            assert field in caption

    def test_footer_lists_exactly_what_parses(self):
        """Test no spelling appears in the footer that the parser would reject."""
        caption = self._caption(["?", "s-1vcpu-1gb"])
        for spelling in ("memory", "ram", "vcpus", "cpus", "vcpu"):
            assert spelling not in caption

    def test_every_operator_is_listed(self):
        """Test the footer names each comparison operator."""
        caption = self._caption(["?", "s-1vcpu-1gb"])
        for op in (">=", "<=", ">", "<", "="):
            assert op in caption

    def test_units_are_listed(self):
        """Test the accepted unit suffixes are named."""
        caption = self._caption(["?", "s-1vcpu-1gb"])
        for unit in ("gb", "mb", "tb"):
            assert unit in caption

    def test_no_keywords_for_data_without_numeric_fields(self):
        """Test a region table is not captioned with size filter syntax."""
        caption = self._caption(["?", "nyc3"], data=[{"slug": "nyc3", "name": "New York 3"}])
        assert caption == ""


class TestFilterableFields:
    """Tests for which field names the prompt advertises."""

    def test_size_fields_in_table_order(self):
        """Test a size list offers every numeric field, ordered like the table."""
        assert _filterable_fields(SIZES) == ["mem", "cpu", "disk", "transfer", "price"]

    def test_regions_offer_nothing(self):
        """Test a region list advertises no filters, since it has no numeric fields."""
        assert _filterable_fields([{"slug": "nyc3", "name": "New York 3"}]) == []

    def test_partial_data_offers_only_what_it_has(self):
        """Test only fields actually present are advertised."""
        assert _filterable_fields([{"slug": "x", "vcpus": 1}]) == ["cpu"]

    def test_empty_and_none_are_safe(self):
        """Test no data means no advertised filters."""
        assert _filterable_fields([]) == []
        assert _filterable_fields(None) == []

    def test_union_across_rows(self):
        """Test a field present on only some rows is still advertised."""
        rows = [{"slug": "a", "vcpus": 1}, {"slug": "b", "memory": 1024}]
        assert _filterable_fields(rows) == ["mem", "cpu"]


class TestSyntaxHintIsShownUpFront:
    """Tests that the filter syntax is visible before any mistake is made."""

    def _output(self, data):
        """Run the prompt once and return everything printed to the console."""
        with (
            patch("dropkit.ui.Prompt.ask", side_effect=["nyc3"]),
            patch("dropkit.ui.console.print") as printed,
        ):
            prompt_with_help("Thing", "nyc3", MagicMock(), data)
        return "\n".join(str(c.args[0]) if c.args else "" for c in printed.call_args_list)

    def test_syntax_shown_without_needing_an_error(self):
        """Test the fields and operators are printed before the first prompt."""
        out = self._output(SIZES)
        assert "cpu" in out
        assert ">=" in out

    def test_example_is_copyable(self):
        """Test the hint includes a concrete example, not just a grammar."""
        assert "? cpu>=4 mem>=16 price<=150" in self._output(SIZES)

    def test_no_size_syntax_at_a_region_prompt(self):
        """Test a region list is not told it can filter on cpu."""
        out = self._output([{"slug": "nyc3", "name": "New York 3"}])
        assert "cpu" not in out
        assert "narrow with" not in out


class TestPromptWithHelp:
    """Tests for the prompt loop, including the '?<filter>' branch."""

    def test_plain_value_returned_immediately(self):
        """Test a normal answer is returned without listing anything."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-1vcpu-1gb"
        display.assert_not_called()

    def test_bare_question_mark_lists_everything(self):
        """Test '?' passes the full, unfiltered data set."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["?", "s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-1vcpu-1gb"
        display.assert_called_once()
        assert display.call_args.args[0] == SIZES

    def test_filter_without_a_question_mark_still_filters(self):
        """Test a forgotten '?' does not send the expression back as a slug."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["cpu>=4", "g-4vcpu-16gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "g-4vcpu-16gb"
        assert [s["slug"] for s in display.call_args.args[0]] == ["s-4vcpu-8gb", "g-4vcpu-16gb"]

    def test_bad_filter_without_a_question_mark_reprompts(self):
        """Test a malformed filter re-prompts instead of aborting the command."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["memy > 15", "s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-1vcpu-1gb"
        display.assert_not_called()

    def test_operator_in_input_is_returned_when_data_cannot_be_filtered(self):
        """Test a region or project answer containing '>' is not hijacked as a filter."""
        display = MagicMock()
        regions = [{"slug": "nyc3", "name": "New York 3"}]
        with patch("dropkit.ui.Prompt.ask", side_effect=["a > b"]):
            result = prompt_with_help("Project", "x", display, regions)
        assert result == "a > b"

    def test_plain_slug_is_never_treated_as_a_filter(self):
        """Test an ordinary answer with no operator returns immediately."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["s-8vcpu-16gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-8vcpu-16gb"
        display.assert_not_called()

    def test_filter_narrows_the_listing(self):
        """Test '?<filter>' passes only the matching rows."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["? cpu>=4", "g-4vcpu-16gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "g-4vcpu-16gb"
        shown = display.call_args.args[0]
        assert [s["slug"] for s in shown] == ["s-4vcpu-8gb", "g-4vcpu-16gb"]

    def test_filter_caption_reports_counts_and_expression(self):
        """Test the caption names the active filter and how much it hid."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["? cpu>=4", "g-4vcpu-16gb"]):
            prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        caption = display.call_args.kwargs["caption"]
        assert "2 of 4 shown" in caption
        assert "cpu>=4" in caption

    def test_filter_can_be_refined(self):
        """Test the prompt survives a filter so it can be narrowed again."""
        display = MagicMock()
        with patch(
            "dropkit.ui.Prompt.ask",
            side_effect=["? cpu>=4", "? cpu>=4 mem>=16", "g-4vcpu-16gb"],
        ):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "g-4vcpu-16gb"
        assert display.call_count == 2
        last = display.call_args.args[0]
        assert [s["slug"] for s in last] == ["g-4vcpu-16gb"]

    def test_zero_matches_shows_no_table(self):
        """Test an unsatisfiable filter re-prompts without printing a table."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["? cpu>=999", "s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-1vcpu-1gb"
        display.assert_not_called()

    def test_invalid_filter_reprompts(self):
        """Test a bad filter does not end the prompt or print a table."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["? intel", "s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-1vcpu-1gb"
        display.assert_not_called()

    def test_filter_with_markup_characters_does_not_crash(self):
        """Test square brackets in the input are not parsed as Rich markup."""
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["? mem>=[16", "s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb", display, SIZES)
        assert result == "s-1vcpu-1gb"
        display.assert_not_called()

    def test_no_display_func_reports_no_help(self):
        """Test '?' without a display function still returns a usable answer."""
        with patch("dropkit.ui.Prompt.ask", side_effect=["?", "s-1vcpu-1gb"]):
            result = prompt_with_help("Size", "s-1vcpu-1gb")
        assert result == "s-1vcpu-1gb"

    def test_filter_on_data_without_numeric_fields(self):
        """Test filtering a region list (no numeric fields) reports no matches."""
        regions = [{"slug": "nyc3", "name": "New York 3"}]
        display = MagicMock()
        with patch("dropkit.ui.Prompt.ask", side_effect=["? cpu>=4", "nyc3"]):
            result = prompt_with_help("Region", "nyc3", display, regions)
        assert result == "nyc3"
        display.assert_not_called()
