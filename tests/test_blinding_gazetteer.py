"""
Gazetteer-based blinding: lower-case names, single first names, street addresses, place names and
cued organisation names, plus the guards that keep ordinary business/technical prose untouched.
"""

import asyncio
import os
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.crypto import gazetteer  # noqa: E402
from backend.crypto.blind_tokenizer import MAX_PROMPT_CHARS, BlindTokenizer  # noqa: E402

_TOKEN_RE = re.compile(r"\[(?:ID|LOC|GOV_ID|IBAN|EMAIL|PHONE|SECRET)_[0-9A-F]{8}\]")
_FHE_RE = re.compile(r"\[FHE_NUM_\d+\]\(ENC:[^)]*\)")


class GazetteerBlindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tok = BlindTokenizer(paillier_bits=1024)

    def blind(self, prompt):
        return self.tok.blind_prompt(prompt)

    def assert_hidden(self, prompt, pieces, category=None):
        blinded, ctx = self.blind(prompt)
        # Strip tokens first: a short piece such as "4b" can occur inside a token's hex digest.
        clear = _FHE_RE.sub(" ", _TOKEN_RE.sub(" ", blinded)).lower()
        for piece in pieces:
            self.assertNotIn(piece.lower(), clear, msg=f"{piece!r} leaked in {blinded!r}")
        if category:
            self.assertIn(f"[{category}_", blinded)
        self.assertEqual(self.tok.residual_scan(blinded, ctx)["residual_matches"], 0)
        return blinded, ctx

    # --- the four leak groups ----------------------------------------------------------------
    def test_lowercase_full_names_after_a_person_cue(self):
        for prompt, pieces in [
            ("transfer to jan jansen", ["jan", "jansen"]),
            ("mail maria de vries", ["maria", "vries"]),
            ("Stuur de factuur naar piet de boer", ["piet", "boer"]),
            ("bel met sanne van den berg", ["sanne", "berg"]),
            ("for will smith and to bill gates", ["will smith", "bill gates"]),
            ("ping max verstappen", ["max verstappen"]),
            ("Ask lisa about the numbers", ["lisa"]),
            ("send it to sem", [" sem"]),
            ("Send to José García López", ["José", "García", "López"]),
        ]:
            with self.subTest(prompt=prompt):
                self.assert_hidden(prompt, pieces, "ID")

    def test_single_first_names(self):
        blinded, _ = self.assert_hidden("Send the report to Sem about Maria", ["Sem", "Maria"], "ID")
        self.assertTrue(blinded.startswith("Send the report to [ID_"))
        for prompt, pieces in [
            ("Hi Sem, can you check this?", ["Sem"]),
            ("Dear Maria, thanks for the update.", ["Maria"]),
            ("Emma approved the budget.", ["Emma"]),
            ("Talk to Will about the budget.", ["Will"]),
            ("Hannah's report is late", ["Hannah"]),
        ]:
            with self.subTest(prompt=prompt):
                self.assert_hidden(prompt, pieces, "ID")

    def test_addresses_and_places(self):
        cases = [
            ("lives at Keizersgracht 12, Amsterdam", ["Keizersgracht", "12", "Amsterdam"]),
            ("Stationsweg 4b in Utrecht", ["Stationsweg", "4b", "Utrecht"]),
            ("12 Baker Street, London", ["Baker", "12", "London"]),
            ("Ship to 221B Baker Street.", ["221B", "Baker"]),
            ("Kalverstraat 92-94 is closed", ["Kalverstraat", "92", "94"]),
            ("Kerkstraat 12 bis", ["Kerkstraat", "12"]),
            ("Hoofdweg 12-hs, Amsterdam", ["Hoofdweg", "12", "Amsterdam"]),
            ("Prins Hendrikkade 33 te Amsterdam", ["Hendrikkade", "33", "Amsterdam"]),
            ("woont aan de Keizersgracht", ["Keizersgracht"]),
            ("address: Baker Street", ["Baker"]),
            ("Ga naar Den Haag en daarna naar 's-Hertogenbosch", ["Haag", "Hertogenbosch"]),
            ("Ga naar Den Bosch of Bergen op Zoom", ["Bosch", "Zoom"]),
            ("Office in New York and The Hague", ["York", "Hague"]),
            ("Moving to Reading next year; meet near Nice.", ["Reading", "Nice"]),
            ("Made in Holland, born in Best.", ["Best"]),
        ]
        for prompt, pieces in cases:
            with self.subTest(prompt=prompt):
                blinded, ctx = self.assert_hidden(prompt, pieces, "LOC")
                self.assertNotIn("[FHE_NUM_", blinded)  # house numbers belong to the LOC span
        # The whole address, house number included, is one LOC value.
        _, ctx = self.blind("lives at Keizersgracht 12, Amsterdam")
        self.assertIn("Keizersgracht 12", ctx.token_to_plaintext.values())
        self.assertIn("Amsterdam", ctx.token_to_plaintext.values())

    def test_cued_organisations_keep_the_cue_word_in_clear(self):
        blinded, ctx = self.assert_hidden(
            "Pay Total Security and Cloud Reserve today", ["Total Security", "Cloud Reserve"], "ID"
        )
        self.assertTrue(blinded.startswith("Pay [ID_"))
        self.assertTrue(blinded.endswith(" today"))
        self.assertEqual(set(ctx.token_to_plaintext.values()), {"Total Security", "Cloud Reserve"})

        blinded, ctx = self.assert_hidden(
            "Invoice from Master Audit for Johnny Cash", ["Master Audit", "Johnny", "Cash"], "ID"
        )
        self.assertTrue(blinded.startswith("Invoice from [ID_"))
        for prompt, piece in [
            ("factuur van Groene Energie Nederland", "Groene Energie"),
            ("leverancier Bol Partners levert morgen", "Bol Partners"),
            ("betaal Rabo Lease vandaag", "Rabo Lease"),
            ("The company Annual Report is due", "Annual Report"),
        ]:
            with self.subTest(prompt=prompt):
                self.assert_hidden(prompt, [piece], "ID")
        # Without a cue word the business-noun rule still applies.
        for sentence in ["Review Annual Bonus and Balance Sheet today.", "Pay the Annual Bonus to staff"]:
            with self.subTest(sentence=sentence):
                self.assertEqual(self.blind(sentence)[0], sentence)

    def test_ambiguous_names_need_extra_evidence(self):
        for sentence in [
            "mark the invoice as paid",
            "will pay later",
            "moved to max capacity",
            "met mark overleggen",
            "set this to max",
            "the emma project",
            "the julia notebook crashed",
            "Revenue grew from May to June.",
            "The deadline moved to April.",
            "Ik ben morgen weg.",
            "Dan gaan we verder.",
            "Wil je dit nakijken?",
            "we gaan naar huis",
        ]:
            with self.subTest(sentence=sentence):
                self.assertEqual(self.blind(sentence)[0], sentence)

    # --- primary subject -------------------------------------------------------------------------
    def test_primary_subject_still_prefers_the_role_subject(self):
        for prompt, subject in [
            ("Review Annual Bonus and Balance Sheet for employee Marcus Vance today.", "Marcus Vance"),
            ("Send the report to Sem in Amsterdam about employee Marcus Vance.", "Marcus Vance"),
            ("Ship to Keizersgracht 12, Utrecht for patient Sophia Laurent", "Sophia Laurent"),
            ("Pay Total Security for employee jan jansen", "jan jansen"),
            ("Bonus for employee Maria van der Berg and Jan Jansen", "Maria van der Berg"),
            ("Jan Jansen approves bonus for patient O'Connor", "O'Connor"),
            ("Process record for Sophia Laurent (clinic: Amsterdam Central)", "Sophia Laurent"),
        ]:
            with self.subTest(prompt=prompt):
                _, ctx = self.blind(prompt)
                self.assertEqual(ctx.token_to_plaintext[ctx.primary_subject_token], subject)
        # A place is never the subject.
        _, ctx = self.blind("Move the office from Amsterdam to Den Haag.")
        self.assertEqual(ctx.primary_subject_token, "")

    def test_name_place_disambiguation_and_apostropheless_dutch_cities(self):
        # Role/person cues on city-homograph names classify as ID (and can be primary_subject_token).
        for prompt, expected_subject in [
            ("Evaluate a bonus for employee Austin today.", "Austin"),
            ("Medewerker Milan werkt vandaag thuis.", "Milan"),
            ("Send the report to Sofia tomorrow.", "Sofia"),
            ("Stuur het rapport naar Anders voor controle.", "Anders"),
            ("Anders Lindqvist approved the budget.", "Anders Lindqvist"),
        ]:
            with self.subTest(prompt=prompt):
                blinded, ctx = self.assert_hidden(prompt, [expected_subject], "ID")
                self.assertEqual(ctx.token_to_plaintext[ctx.primary_subject_token], expected_subject)
                self.assertNotIn("[LOC_", blinded)

        # Place prepositions classify ambiguous NL/world places and apostrophe-less s- cities as LOC.
        for prompt, pieces in [
            ("Our office in Sofia and branch at Austin are open.", ["Sofia", "Austin"]),
            ("Kantoor in Houten, filiaal in Weert en opslag bij Duiven.", ["Houten", "Weert", "Duiven"]),
            ("Overleg in s-Hertogenbosch en daarna in s-Gravenhage.", ["Hertogenbosch", "Gravenhage"]),
        ]:
            with self.subTest(prompt=prompt):
                self.assert_hidden(prompt, pieces, "LOC")

    # --- ordinary prose stays literally the same --------------------------------------------------
    PROSE_UNCHANGED = [
        "Will the report be ready in May?",
        "Mark this as done.",
        "We hope to grow in Q4.",
        "Best regards",
        "Best regards, the finance team.",
        "Please review the travel policy before Friday.",
        "The quarterly planning session moves to next Tuesday.",
        "Revenue grew from May to June and dipped in August.",
        "Our roadmap targets a beta in March and launch in June.",
        "Can you mark the invoice as paid?",
        "We will pay the supplier later this week.",
        "Grace periods apply to late payments.",
        "Faith in the forecast is low this quarter.",
        "Reading the logs helps with debugging.",
        "Nice work on the release, team.",
        "Split the bill between the two departments.",
        "Made with care by the platform team.",
        "Born out of a hackathon, the tool now serves many teams.",
        "The mobile app needs a new login screen.",
        "Deploy the service to the staging cluster tonight.",
        "Merge the pull request after the tests pass.",
        "Our churn dropped while the conversion rate improved.",
        "Hope you had a good weekend.",
        "Art direction for the campaign is still open.",
        "Max out the retry budget before failing over.",
        "Ray tracing is not supported on this device.",
        "Mark the date in your calendar: the review is in June.",
        "Review Fiscal Year and Fiscal Quarter results.",
        "Send the report to the client by Friday.",
        "Check the Service Level Agreement before signing.",
        "Goes it well with the release?",
        "Remember that a password is never requested by support staff.",
        "The password policy was updated last week.",
        "De vergadering is verplaatst naar donderdag.",
        "We verwachten in het vierde kwartaal meer omzet.",
        "Ik ben morgen de hele dag op kantoor.",
        "Dan plannen we de evaluatie in mei.",
        "Wil je het beleid voor thuiswerken nog nakijken?",
        "Het team werkt aan een nieuwe versie van de app.",
        "De arbeidsmarkt blijft krap in de zorg.",
        "Onderweg naar de klant hebben we de offerte besproken.",
        "Echt waar, de cijfers kloppen.",
        "Leiden tot betere resultaten is ons doel.",
        "De sleutel tot succes is goede samenwerking met onze klanten.",
        "Het geheim van ons kwartaalresultaat is focus op kwaliteit.",
        "Anders moeten we het project uitstellen.",
        "Anders dan verwacht daalde de omzet.",
        "Weert de nieuwe firewall dit verkeer?",
        "Houten meubels zijn dit jaar duurder.",
        "Duiven zorgen voor overlast op het dak.",
        "Wenen heeft geen zin na een fout.",
        "Hulst groeit goed in de winter.",
        "Revenue grew from Jan to Mar.",
        "The contract was signed in Jan.",
        "Demand started to peter out.",
    ]

    def test_ordinary_prose_is_unchanged(self):
        self.assertGreaterEqual(len(self.PROSE_UNCHANGED), 40)
        for sentence in self.PROSE_UNCHANGED:
            with self.subTest(sentence=sentence):
                blinded, ctx = self.blind(sentence)
                self.assertEqual(blinded, sentence)
                self.assertEqual(len(ctx.sealed_secrets), 0)

    def test_prose_where_only_specific_parts_may_be_blinded(self):
        # (sentence, must be hidden, must stay literally present)
        cases = [
            ("The team will meet in the Amsterdam office", ["Amsterdam"], ["The team will meet in the ", " office"]),
            ("The board will meet in the Amsterdam office on Monday.", ["Amsterdam"], [" office on Monday."]),
            ("We need 2048 MB and ISO27001 by Q4FY2026.", ["2048"], ["We need ", " MB and ISO27001 by Q4FY2026."]),
            ("Our team in Utrecht ships the release in May.", ["Utrecht"], ["Our team in ", " ships the release in May."]),
            # A year after a street-like word is not a house number.
            ("Woningmarkt 2025 in cijfers", ["2025"], ["Woningmarkt ", " in cijfers"]),
        ]
        for sentence, hidden, kept in cases:
            with self.subTest(sentence=sentence):
                blinded, _ = self.blind(sentence)
                for piece in hidden:
                    self.assertNotIn(piece, _FHE_RE.sub(" ", _TOKEN_RE.sub(" ", blinded)))
                for piece in kept:
                    self.assertIn(piece, blinded)
                rest = _FHE_RE.sub("", _TOKEN_RE.sub("", blinded))
                self.assertNotIn("[", rest)

    # --- gazetteer contents ------------------------------------------------------------------------
    def test_gazetteer_sizes_and_hygiene(self):
        self.assertGreaterEqual(len(gazetteer.FIRST_NAMES), 600)
        self.assertGreaterEqual(len(gazetteer.PLACE_NAMES), 300)
        self.assertIn("den haag", gazetteer.PLACE_NAMES)
        self.assertIn("new york", gazetteer.PLACE_NAMES)
        self.assertTrue(gazetteer.AMBIGUOUS_FIRST_NAMES <= gazetteer.FIRST_NAMES)
        self.assertTrue(gazetteer.AMBIGUOUS_PLACES <= gazetteer.PLACE_NAMES)
        for name in gazetteer.FIRST_NAMES | gazetteer.PLACE_NAMES:
            self.assertEqual(name, name.lower())
        # Short words that are articles/pronouns in EN or NL are never first names.
        for word in ["an", "al", "ad", "ed", "can", "said", "do", "the", "de", "het"]:
            self.assertNotIn(word, gazetteer.FIRST_NAMES)

    # --- adversarial input stays fast ------------------------------------------------------------
    def test_hostile_inputs_finish_within_one_second(self):
        def fit(unit):
            return (unit * (MAX_PROMPT_CHARS // len(unit) + 1))[:MAX_PROMPT_CHARS]

        prompts = {
            "jan": fit("jan "),
            "to-jan-jansen": fit("to jan jansen "),
            "to-will": fit("to will "),
            "capitalised-names": fit("Maria "),
            "capitalised-words": fit("Abcdef "),
            "no-spaces": fit("A"),
            "particles": fit("Van Der De "),
            "addresses": fit("Keizersgracht 12 "),
            "places": fit("Den "),
            "org-cue": fit("Pay Total Security and "),
            "firm-list": fit("firm Abc Def Ghi Jkl, "),
            "en-street-words": fit("Baker Baker Baker Street "),
            "mixed": fit("transfer to jan de vries in Den Haag at Kerkstraat 4b, "),
        }
        for name, prompt in prompts.items():
            with self.subTest(name=name):
                t0 = time.perf_counter()
                self.blind(prompt)
                self.assertLess(time.perf_counter() - t0, 1.0)
        # Span collection itself, on inputs far beyond the prompt limit (60,000 x "jan ").
        for unit in ["jan ", "to jan ", "Abcdef ", "12 Baker Baker Baker "]:
            with self.subTest(unit=unit):
                t0 = time.perf_counter()
                self.tok._collect_spans(unit * 60_000 if len(unit) <= 7 else unit * 12_000)
                self.assertLess(time.perf_counter() - t0, 1.0)


class PresetRegressionTests(unittest.TestCase):
    """The five UI presets in frontend/static/app.js keep their end results."""

    @classmethod
    def setUpClass(cls):
        from services.pipeline_service import AgentPipeline

        cls._tmp = tempfile.TemporaryDirectory()
        cls.pipe = AgentPipeline(storage_dir=cls._tmp.name, reset_vault=True, paillier_bits=1024)
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with open(os.path.join(root, "frontend", "static", "app.js"), encoding="utf-8") as fh:
            src = fh.read()
        start = src.index("salary:")
        block = src[start : src.index("};", start)]
        cls.presets = dict(re.findall(r'(\w+):\s*"((?:[^"\\]|\\.)*)"', block))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, key):
        return asyncio.run(self.pipe.process_prompt(self.presets[key], provider="simulation"))

    def test_preset_end_results(self):
        self.assertEqual(set(self.presets), {"salary", "bfv_secrets", "health", "finance", "xss"})
        expected_outputs = {
            "salary": {"[FHE_COMPUTED_BONUS]": "$19,500.00", "[FHE_COMPUTED_TOTAL]": "$149,500.00"},
            "bfv_secrets": {"[FHE_COMPUTED_PRODUCT]": "$36,000"},
            "xss": {"[FHE_COMPUTED_BONUS]": "$30,000.00", "[FHE_COMPUTED_TOTAL]": "$180,000.00"},
        }
        for key, outputs in expected_outputs.items():
            with self.subTest(preset=key):
                res = self._run(key)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["fhe_computation"]["decrypted_outputs"], outputs)
        for key, action in [("health", "UPDATE_EHR_LEDGER"), ("finance", "TRANSFER_EXECUTE")]:
            with self.subTest(preset=key):
                res = self._run(key)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertEqual(res["enclave_receipt"]["action"], action)

    def test_preset_subjects_and_clinic_location(self):
        tok = self.pipe.tokenizer
        for key, subject in [
            ("salary", "Marcus Vance"),
            ("bfv_secrets", "Nova Labs"),
            ("health", "Sophia Laurent"),
            ("finance", "Acronis Corp"),
            ("xss", "Elena Rostova"),
        ]:
            with self.subTest(preset=key):
                blinded, ctx = tok.blind_prompt(self.presets[key])
                self.assertEqual(ctx.token_to_plaintext[ctx.primary_subject_token], subject)
        blinded, ctx = tok.blind_prompt(self.presets["health"])
        self.assertIn("Amsterdam Central", ctx.token_to_plaintext.values())
        self.assertIn("clinic: [LOC_", blinded)

class TestLowerCaseNameWithParticle(unittest.TestCase):
    def test_lower_case_name_with_particle_needs_no_cue(self):
        from backend.crypto.blind_tokenizer import BlindTokenizer

        tok = BlindTokenizer(paillier_bits=1024)
        for prompt, forbidden in [
            ("ask whether jan de vries can join the call", "jan de vries"),
            ("the report says maria van dijk approved it", "maria van dijk"),
            ("and pieter van der berg signed", "pieter van der berg"),
        ]:
            with self.subTest(prompt=prompt):
                blinded, _ = tok.blind_prompt(prompt)
                self.assertNotIn(forbidden, blinded)
        # Ambiguous first names and plain words stay untouched.
        for sentence in [
            "we will de facto accept the terms",
            "mark de deadline in de agenda",
            "the team met in de ochtend",
        ]:
            with self.subTest(sentence=sentence):
                blinded, _ = tok.blind_prompt(sentence)
                self.assertEqual(blinded, sentence)


if __name__ == "__main__":
    unittest.main()
