#!/usr/bin/env python3
"""Unit tests for the sanitizer engine, config handling, file decoding and CLI."""

import codecs
import json
import os
import tempfile
import unittest

import log_sanitizer as L
from log_sanitizer import (
    SanitizerEngine,
    SanitizationPattern,
    compile_regex,
    is_risky_regex,
    make_pattern,
)


class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = SanitizerEngine()

    def clean(self, text):
        return self.engine.sanitize(text)[0]


class TestBuiltins(EngineTestCase):
    def test_email_and_valid_ip(self):
        out, counts = self.engine.sanitize("contact me@example.com from 192.168.1.10")
        self.assertEqual(out, "contact <EMAIL> from <IP>")
        self.assertEqual(counts, {"Email": 1, "IP": 1})

    def test_invalid_ip_not_matched(self):
        out, counts = self.engine.sanitize("bad 999.999.999.999 ok 10.0.0.1")
        self.assertIn("999.999.999.999", out)
        self.assertNotIn("10.0.0.1", out)
        self.assertEqual(counts.get("IP", 0), 1)

    def test_ip_port_priority_over_ip(self):
        self.assertEqual(self.clean("connect 10.0.0.5:8080 now"), "connect <IP>:<PORT> now")

    def test_password_variants_keep_key_and_hide_value(self):
        for text in ("password: hunter2", "PASSWORD=hunter2", "Password = hunter2", "pwd:hunter2",
                     '"password": "hunter2"', "DB_PASSWORD=hunter2", "url?passwd=hunter2&x=1"):
            out = self.clean(text)
            self.assertNotIn("hunter2", out, text)
            self.assertIn("<HASHED_PASSWORD_", out, text)
        self.assertTrue(self.clean("PASSWORD=admin123!").startswith("PASSWORD=<HASHED_PASSWORD_"))

    def test_space_separator_only_for_explicit_secret_keys(self):
        self.assertNotIn("abc123xyz", self.clean("api_key abc123xyz"))
        self.assertNotIn("tok9", self.clean("access_token tok9"))
        self.assertEqual(self.clean("Invalid token for user"), "Invalid token for user")

    def test_identical_span_keeps_higher_priority(self):
        out = self.clean("refresh_token=r1 Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc")
        self.assertIn("refresh_token=<HASHED_REFRESHTOKEN_", out)
        self.assertIn("Bearer <HASHED_JWTTOKEN_", out)

    def test_quoted_value_with_spaces(self):
        out = self.clean("secret='correct horse battery'")
        self.assertNotIn("horse", out)
        self.assertRegex(out, r"^secret='<HASHED_SECRETKEY_[0-9A-F]+>'$")

    def test_same_value_same_hash_within_run(self):
        out = self.clean("password=abc pwd=abc password=xyz")
        tokens = out.split()
        self.assertEqual(tokens[0].split("=")[1], tokens[1].split("=")[1])
        self.assertNotEqual(tokens[0].split("=")[1], tokens[2].split("=")[1])

    def test_tokens_and_keys(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
        cases = {
            f"token {jwt} end": jwt,
            "Authorization: Bearer abcdefghijklmnop": "abcdefghijklmnop",
            "aws AKIAIOSFODNN7EXAMPLE used": "AKIAIOSFODNN7EXAMPLE",
            "refresh_token=r3fr3sh": "r3fr3sh",
            "access-token: t0k3n": "t0k3n",
            "x-api-key: k3y": "k3y",
        }
        for text, secret in cases.items():
            self.assertNotIn(secret, self.clean(text), text)

    def test_url_credentials(self):
        out = self.clean("fetch https://bob:p@ss@git.example.org/repo.git")
        self.assertEqual(out, "fetch https://<CREDENTIALS>@git.example.org/repo.git")

    def test_database_url_absorbs_inner_matches(self):
        out = self.clean("DATABASE_URL=postgres://admin:S3cret@10.0.0.5:5432/prod")
        self.assertRegex(out, r"^DATABASE_URL=<HASHED_DATABASEURL_[0-9A-F]+>$")

    def test_lower_priority_wider_match_absorbs(self):
        out = self.clean("DisplayName=John Smith <john@corp.com>, dept=IT")
        self.assertEqual(out, "DisplayName=<USER>, dept=IT")

    def test_connection_string(self):
        out = self.clean("connectionString=Server=db1;User Id=sa;Password=pw;")
        self.assertNotIn("pw", out.replace("<HASHED", ""))
        self.assertIn("<HASHED_CONNECTIONSTRING_", out)

    def test_private_key_block(self):
        text = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----\ndone"
        self.assertEqual(self.clean(text), "key:\n<PRIVATE_KEY>\ndone")

    def test_credit_card_luhn(self):
        self.assertEqual(self.clean("card 4111 1111 1111 1111 ok"), "card <CARD> ok")
        self.assertIn("4111 1111 1111 1112", self.clean("card 4111 1111 1111 1112 ok"))

    def test_ipv6_validated(self):
        self.assertEqual(self.clean("from fe80::1ff:fe23:4567:890a%eth0 at 14:35:22"), "from <IPV6> at 14:35:22")
        self.assertEqual(self.clean("C++ std::vector"), "C++ std::vector")

    def test_mac_guid_sid(self):
        out = self.clean("mac 00:1A:2B:3C:4D:5E guid 123E4567-E89B-12D3-A456-426614174000 sid S-1-5-21-1-2-3-500")
        self.assertTrue(out.startswith("mac <MAC> guid <GUID> sid <HASHED_SID_"))

    def test_home_paths_any_user(self):
        self.assertEqual(self.clean(r"C:\Users\John Smith\AppData\x.log"), r"C:\Users\<USERNAME>\AppData\x.log")
        self.assertEqual(self.clean("/home/alice/.ssh"), "/home/<USERNAME>/.ssh")
        self.assertEqual(self.clean(r"C:\Users\Public\Documents"), r"C:\Users\Public\Documents")

    def test_ad_attributes_and_ldap(self):
        out = self.clean("sAMAccountName: jdoe, distinguishedName=CN=Doe\\, John,OU=Staff,DC=corp")
        self.assertEqual(out, "sAMAccountName: <USER>, distinguishedName=CN=<USER>,OU=Staff,DC=corp")

    def test_port_spec(self):
        self.assertEqual(self.clean("listening on port 8443"), "listening on port <PORT>")
        self.assertEqual(self.clean("report 5 items"), "report 5 items")

    def test_placeholders_not_rematched(self):
        out = self.clean("user john@example.com")
        self.assertEqual(out, "user <EMAIL>")


class TestPatterns(EngineTestCase):
    def test_hmac_stable_within_run_differs_across_runs(self):
        self.engine.patterns = {
            "Password": SanitizationPattern("Password", compile_regex(r"password=([^\s]+)", 0),
                                            "password=<PASSWORD>", True, priority=90)
        }
        self.engine.invalidate_pattern_cache()
        sample = "password=secret123"
        out1, _ = self.engine.sanitize(sample)
        out2, _ = self.engine.sanitize(sample)
        self.assertIn("<HASHED_PASSWORD_", out1)
        self.assertNotEqual(out1, out2)
        salt = b"fixed-salt-for-apply-test-0001"
        a, _ = self.engine.patterns["Password"].apply(sample, salt)
        b, _ = self.engine.patterns["Password"].apply(sample, salt)
        self.assertEqual(a, b)

    def test_value_group_and_templates(self):
        p = make_pattern("Order", r"order=(?P<value>\d+)", "<ORDER>")
        self.assertEqual(p.apply("order=123 x")[0], "order=<ORDER> x")
        t = make_pattern("Swap", r"(\w+)@(\w+)", r"\2 at \1")
        self.assertEqual(t.apply("me@host")[0], "host at me")
        lit = make_pattern("Dom", r"corp\\[a-z]+", "<DOMAIN\\USERNAME>")
        self.assertEqual(lit.apply("corp\\bob")[0], "<DOMAIN\\USERNAME>")

    def test_hash_tag_safe_name(self):
        p = make_pattern("MAC Address", r"aa:bb", "<MAC>", hash_flag=True)
        self.assertRegex(p.apply("aa:bb")[0], r"^<HASHED_MAC_ADDRESS_[0-9A-F]{12}>$")

    def test_make_pattern_validation(self):
        for args in (("", "x", "y"), ("n", "", "y"), ("n", "(", "y"), ("n", "(a+)+", "y")):
            with self.assertRaises(ValueError):
                make_pattern(*args)

    def test_risky_regex_detected(self):
        self.assertTrue(is_risky_regex(r"(a+)+"))
        self.assertFalse(is_risky_regex(r"\b\d{3}-\d{4}\b"))

    def test_disabled_and_test_pattern(self):
        self.engine.enable_named_patterns(["Email"], False)
        self.assertIn("a@b.com", self.clean("a@b.com"))
        ok, result, count = self.engine.test_pattern("Email", "a@b.com")  # testing ignores enabled
        self.assertTrue(ok)
        self.assertEqual((result, count), ("<EMAIL>", 1))


class TestConfig(EngineTestCase):
    def write(self, tmp, patterns, name="cfg.json"):
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"patterns": patterns}, fh)
        return path

    def test_custom_pattern_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, msg = self.engine.load_config(self.write(tmp, [{
                "name": "PhoneLite", "regex": r"\b555-\d{4}\b", "replacement": "<PHONE>", "hash": False,
                "enabled": False, "case_sensitive": True, "priority": 42, "comment": "test"}]))
        self.assertTrue(ok, msg)
        p = self.engine.patterns["PhoneLite"]
        self.assertFalse(p.enabled)
        self.assertEqual(p.priority, 42)
        self.assertTrue(p.case_sensitive)

    def test_risky_and_invalid_entries_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            ok, msg = self.engine.load_config(self.write(tmp, [
                {"name": "Evil", "regex": r"(a+)+", "replacement": "x"},
                {"name": "Broken", "regex": "(", "replacement": "x"},
                {"name": "Good", "regex": "foo", "replacement": "<FOO>"},
            ]))
        self.assertTrue(ok)
        self.assertIn("skipped 2", msg)
        self.assertNotIn("Evil", self.engine.patterns)
        self.assertIn("Good", self.engine.patterns)

    def test_override_builtin_without_regex(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.engine.load_config(self.write(tmp, [{"name": "Email", "enabled": False}]))
        self.assertFalse(self.engine.patterns["Email"].enabled)
        self.assertIn("a@b.com", self.clean("a@b.com"))

    def test_legacy_copied_builtin_keeps_improved_default(self):
        legacy = {"name": "Password", "regex": r"\b(?:password|PASSWORD|pwd|PWD)(?:\s+|=|:)([^\s,;]+)",
                  "replacement": "password=<PASSWORD>", "hash": True}
        ipport = {"name": "IPPort", "regex": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b",
                  "replacement": "<IP>:<PORT>"}
        with tempfile.TemporaryDirectory() as tmp:
            self.engine.load_config(self.write(tmp, [legacy, ipport]))
        self.assertNotIn("hunter2", self.clean("password: hunter2"))
        self.assertEqual(self.engine.patterns["IPPort"].priority, 100)
        self.assertEqual(self.clean("10.0.0.1:80"), "<IP>:<PORT>")

    def test_override_inherits_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.engine.load_config(self.write(tmp, [{"name": "IP", "regex": r"\b10\.\d+\.\d+\.\d+\b",
                                                      "replacement": "<IP10>"}]))
        self.assertEqual(self.engine.patterns["IP"].priority, 40)

    def test_bad_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(self.engine.load_config(os.path.join(tmp, "missing.json"))[0])
            bad = os.path.join(tmp, "bad.json")
            with open(bad, "w") as fh:
                fh.write("{not json")
            self.assertFalse(self.engine.load_config(bad)[0])
            self.assertFalse(self.engine.load_config(self.write(tmp, None))[0])

    def test_save_load_roundtrip(self):
        self.engine.set_pattern(make_pattern("Ticket", r"TCK-\d+", "<TICKET>", priority=7, examples=["TCK-1"]))
        self.engine.enable_named_patterns(["Hostname", "Email"], False)
        sample = "TCK-42 me@x.com 10.0.0.1"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.json")
            self.engine.save_config(path)
            with open(path, encoding="utf-8") as fh:
                saved = {p["name"]: p for p in json.load(fh)["patterns"]}
            self.assertNotIn("regex", saved["Email"])  # built-ins saved as overrides only
            self.assertEqual(saved["Ticket"]["examples"], ["TCK-1"])
            fresh = SanitizerEngine()
            self.assertTrue(fresh.load_config(path)[0])
        self.assertEqual(fresh.sanitize(sample)[0], self.engine.sanitize(sample)[0])


class TestIO(unittest.TestCase):
    def test_decode_bytes(self):
        text = "user=jos\u00e9 \u05e9\u05dc\u05d5\u05dd"
        self.assertEqual(L.decode_bytes(codecs.BOM_UTF8 + text.encode("utf-8")), (text, "utf-8-sig"))
        self.assertEqual(L.decode_bytes(text.encode("utf-16"))[0], text)
        self.assertEqual(L.decode_bytes(text.encode("utf-16-le"))[0], text)  # no BOM
        self.assertEqual(L.decode_bytes(text.encode("utf-8")), (text, "utf-8"))
        self.assertEqual(L.decode_bytes("caf\u00e9".encode("cp1252")), ("caf\u00e9", "cp1252"))

    def test_sensitive_filename(self):
        self.assertTrue(L.is_sensitive_filename("/x/.env"))
        self.assertTrue(L.is_sensitive_filename("prod.env"))
        self.assertTrue(L.is_sensitive_filename("db_credentials.yaml"))
        self.assertFalse(L.is_sensitive_filename("app.log"))

    def test_cli_writes_sanitized_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "app.log")
            with open(src, "wb") as fh:
                fh.write(b"a@b.com\r\npassword: x1\r\n")
            self.assertEqual(L.run_cli([src, "-q", "-c", os.devnull + "-none"]), 2)  # missing config
            self.assertEqual(L.run_cli([src, "-q"]), 0)
            with open(os.path.join(tmp, "app.sanitized.log"), "rb") as fh:
                out = fh.read().decode("utf-8")
        self.assertTrue(out.startswith("<EMAIL>\r\npassword: <HASHED_PASSWORD_"))


class TestParallel(unittest.TestCase):
    def test_parallel_matches_single_process(self):
        engine = SanitizerEngine()
        block = "-----BEGIN PRIVATE KEY-----\n" + "QUJD\n" * 40 + "-----END PRIVATE KEY-----"
        lines = ["2025-01-01 user=bob from 10.0.0.1:443 mail bob@corp.com", "noise " * 12, block,
                 "token=abc password: p@ss", "fe80::1 and 00:1a:2b:3c:4d:5e"]
        text = "\n".join(lines[i % len(lines)] for i in range(6000))
        old = L.PARALLEL_MIN_CHARS
        L.PARALLEL_MIN_CHARS = 40_000  # force several chunks
        try:
            pats, salt = engine.sorted_patterns(), b"salt"
            single = L.sanitize_text(text, pats, salt, parallel=False)
            with self.assertNoLogs("log_sanitizer", level="WARNING"):  # no silent single-process fallback
                multi = L.sanitize_text(text, pats, salt, parallel=True)
        finally:
            L.PARALLEL_MIN_CHARS = old
        self.assertEqual(single.counts, multi.counts)
        self.assertEqual(single.text, multi.text)
        self.assertNotIn("QUJD", multi.text)


if __name__ == "__main__":
    unittest.main()
