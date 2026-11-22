"""Unit tests for Aman. Stdlib only: python -m unittest tests_aman"""

import json
import os
import tempfile
import unittest

import aman


class TestDetectors(unittest.TestCase):
    def kinds(self, text):
        return {s.kind for s in aman.detect_spans(text)}

    def test_email(self):
        self.assertIn("EMAIL", self.kinds("contact me on foo.bar@example.com please"))

    def test_card_luhn_valid(self):
        # 4242 4242 4242 4242 passes Luhn.
        self.assertIn("CARD", self.kinds("card: 4242 4242 4242 4242"))

    def test_card_luhn_invalid_rejected(self):
        self.assertNotIn("CARD", self.kinds("card: 4242 4242 4242 4241"))

    def test_api_keys(self):
        self.assertIn("API_KEY", self.kinds("key sk-abcdefghij1234567890xyz"))
        self.assertIn("API_KEY", self.kinds("ghp_" + "a1" * 20))

    def test_moroccan_phone(self):
        self.assertIn("PHONE_MA", self.kinds("call +212 6 70 47 29 99"))
        self.assertIn("PHONE_MA", self.kinds("0670472999"))
        self.assertNotIn("PHONE_MA", self.kinds("0512345678"))  # landline range

    def test_cin(self):
        self.assertIn("CIN_MA", self.kinds("CIN: AB123456"))
        self.assertIn("CIN_MA", self.kinds("la carte E458123 ok"))

    def test_ice_requires_hint(self):
        self.assertNotIn("ICE_MA", self.kinds("number 123456789012345 end"))
        self.assertIn("ICE_MA", self.kinds("ICE 123456789012345"))

    def test_iban_ma(self):
        iban = "MA" + "1" * 26
        self.assertIn("IBAN_MA", self.kinds(f"virement {iban}"))

    def test_arabic_honorific(self):
        self.assertIn("PERSON", self.kinds("قلت للسيد يوسف العلوي مرحبا"))
        self.assertIn("PERSON", self.kinds("الدكتورة سارة أمين حضرت"))

    def test_arabic_self_intro(self):
        self.assertIn("PERSON", self.kinds("سميتي إلياس اللمطي"))

    def test_french_honorific(self):
        self.assertIn("PERSON", self.kinds("RDV avec Mme Karima Bennani demain"))
        self.assertIn("PERSON", self.kinds("Je m'appelle Yassine El Fassi"))

    def test_plain_text_clean(self):
        self.assertEqual(set(), self.kinds("the weather is nice today"))
        self.assertEqual(set(), self.kinds("الطقس جميل اليوم فالمغرب"))


class TestRedactRestore(unittest.TestCase):
    def setUp(self):
        self.redactor = aman.Redactor()

    def test_roundtrip(self):
        text = "وصلني إيميل من foo@example.com ورقمي هو 0670472999"
        r = self.redactor.redact(text)
        self.assertNotIn("foo@example.com", r.clean_text)
        self.assertNotIn("0670472999", r.clean_text)
        self.assertEqual(self.redactor.restore(r.clean_text, r.mapping), text)

    def test_stable_placeholders(self):
        r = self.redactor.redact("a@b.co and c@d.co")
        self.assertEqual(
            sorted(r.mapping),
            [aman.PLACEHOLDER_PREFIX + "EMAIL_1__",
             aman.PLACEHOLDER_PREFIX + "EMAIL_2__"],
        )

    def test_overlap_longest_wins(self):
        # A card number containing digits that could match other detectors:
        # only one span should cover it.
        text = "pay with 4242 4242 4242 4242 now"
        spans = aman.detect_spans(text)
        card_spans = [s for s in spans if s.kind == "CARD"]
        self.assertEqual(len(card_spans), 1)

    def test_no_detection(self):
        r = self.redactor.redact("bonjour le monde")
        self.assertEqual(r.clean_text, "bonjour le monde")
        self.assertEqual(r.mapping, {})


class TestStreamingRestorer(unittest.TestCase):
    def test_split_placeholder(self):
        mapping = {aman.PLACEHOLDER_PREFIX + "EMAIL_1__": "foo@example.com"}
        restorer = aman.StreamingRestorer(mapping)
        out = ""
        for chunk in ["voici le mail: __AMAN_P", "II_EMAIL_", "1__ merci"]:
            out += restorer.feed(chunk)
        out += restorer.flush()
        self.assertEqual(out, "voici le mail: foo@example.com merci")

    def test_clean_stream_passes_through(self):
        restorer = aman.StreamingRestorer({})
        out = restorer.feed("hello ") + restorer.feed("world")
        out += restorer.flush()
        self.assertEqual(out, "hello world")

    def test_partial_prefix_in_normal_text(self):
        restorer = aman.StreamingRestorer({})
        out = restorer.feed("a marker __AMAN_PII_UNKNOWN__ here")
        out += restorer.flush()
        self.assertEqual(out, "a marker __AMAN_PII_UNKNOWN__ here")


class TestMessageTransform(unittest.TestCase):
    def test_redact_messages_string_and_parts(self):
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "mon mail est a@b.co"},
            {"role": "user", "content": [
                {"type": "text", "text": "appelez 0670472999"},
                {"type": "image_url", "image_url": {"url": "https://x/y.png"}},
            ]},
        ]
        redactor = aman.Redactor()
        out, mapping = aman.redact_messages(messages, redactor)
        self.assertNotIn("a@b.co", json.dumps(out))
        self.assertNotIn("0670472999", json.dumps(out))
        self.assertEqual(out[0]["content"], "You are helpful.")
        self.assertEqual(out[2]["content"][1]["type"], "image_url")
        self.assertEqual(len(mapping), 2)

    def test_restore_response_body(self):
        mapping = {aman.PLACEHOLDER_PREFIX + "EMAIL_1__": "a@b.co"}
        body = {"choices": [{"message": {"content":
                "Votre email " + aman.PLACEHOLDER_PREFIX + "EMAIL_1__"}}]}
        out = aman.restore_response_body(body, mapping)
        self.assertEqual(out["choices"][0]["message"]["content"],
                         "Votre email a@b.co")

    def test_restore_sse_line(self):
        mapping = {aman.PLACEHOLDER_PREFIX + "PHONE_MA_1__": "0670472999"}
        payload = {"choices": [{"delta": {"content":
                   "le numéro " + aman.PLACEHOLDER_PREFIX + "PHONE_MA_1__"}}]}
        line = "data: " + json.dumps(payload)
        restorer = aman.StreamingRestorer(mapping)
        out = aman.restore_sse_line(line, restorer) + restorer.flush()
        self.assertIn("0670472999", out)

    def test_sse_passthrough(self):
        restorer = aman.StreamingRestorer({})
        self.assertEqual(aman.restore_sse_line("data: [DONE]", restorer),
                         "data: [DONE]")
        self.assertEqual(aman.restore_sse_line(": keep-alive", restorer),
                         ": keep-alive")


class TestAuditLog(unittest.TestCase):
    def test_counts_only_no_values(self):
        secret = "verysecret@example.com"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            log = aman.AuditLog(path)
            log.record("/v1/chat/completions",
                       {aman.PLACEHOLDER_PREFIX + "EMAIL_1__": secret})
            log.record("/v1/chat/completions", {})
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertNotIn(secret, content)
            entry = json.loads(content.strip())
            self.assertEqual(entry["redacted"], {"EMAIL": 1})


if __name__ == "__main__":
    unittest.main()
