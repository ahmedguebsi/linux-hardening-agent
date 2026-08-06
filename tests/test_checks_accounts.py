"""Account and authentication policy check behaviour."""

from __future__ import annotations

from hardening_agent.checks.accounts import (
    EmptyPasswordCheck,
    PasswordMaxDaysCheck,
    RootIsOnlyUidZeroCheck,
    SystemAccountShellCheck,
    _parse_passwd,
)
from hardening_agent.models import RemediationOutcome, Status
from tests.conftest import FakeSystem


class TestPasswdParsing:
    def test_parses_all_seven_fields(self) -> None:
        records = _parse_passwd("root:x:0:0:root:/root:/bin/bash\n")
        assert records == [
            {
                "name": "root",
                "password": "x",
                "uid": "0",
                "gid": "0",
                "gecos": "root",
                "home": "/root",
                "shell": "/bin/bash",
            }
        ]

    def test_malformed_lines_are_skipped_not_fatal(self) -> None:
        """A corrupt line must not abort the whole check."""
        records = _parse_passwd("garbage\nroot:x:0:0:root:/root:/bin/bash\n\n#comment\n")
        assert len(records) == 1
        assert records[0]["name"] == "root"

    def test_gecos_containing_commas_is_preserved(self) -> None:
        records = _parse_passwd("u:x:1:1:Full Name,Room,Work,Home:/home/u:/bin/sh\n")
        assert records[0]["gecos"] == "Full Name,Room,Work,Home"


class TestSingleUidZero:
    def test_only_root_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = (
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
        )
        assert RootIsOnlyUidZeroCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_backdoor_uid_zero_account_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = (
            "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n"
        )
        result = RootIsOnlyUidZeroCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "backdoor" in result.detail
        assert result.evidence["unexpected"] == ["backdoor"]

    def test_unreadable_passwd_is_an_error_not_a_pass(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        """Missing evidence must never be reported as compliance."""
        result = RootIsOnlyUidZeroCheck().audit(make_context(fake_system))
        assert result.status is Status.ERROR


class TestEmptyPasswords:
    def test_empty_password_field_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/shadow"] = "root:$6$hash:19000::::::\nguest::19000::::::\n"
        result = EmptyPasswordCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert result.evidence["accounts"] == ["guest"]

    def test_locked_accounts_are_not_empty(self, fake_system: FakeSystem, make_context) -> None:
        """'!' and '*' are locked, which is the secure state, not an empty password."""
        fake_system.files["/etc/shadow"] = "daemon:*:19000::::::\nsys:!:19000::::::\n"
        assert EmptyPasswordCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_unreadable_shadow_skips(self, fake_system: FakeSystem, make_context) -> None:
        assert EmptyPasswordCheck().audit(make_context(fake_system)).status is Status.SKIP

    def test_remediation_requires_allow_risky(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/shadow"] = "guest::19000::::::\n"
        record = EmptyPasswordCheck().remediate(make_context(fake_system))
        assert record.outcome is RemediationOutcome.SKIPPED
        assert "--allow-risky" in record.detail
        assert fake_system.executed == []

    def test_remediation_locks_accounts_when_permitted(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.files["/etc/shadow"] = "guest::19000::::::\n"
        fake_system.stub(["passwd", "-l", "guest"])
        record = EmptyPasswordCheck().remediate(make_context(fake_system, allow_risky=True))
        assert record.outcome is RemediationOutcome.APPLIED
        assert ("passwd", "-l", "guest") in fake_system.executed


class TestPasswordMaxDays:
    def test_within_limit_passes(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/login.defs"] = "PASS_MAX_DAYS\t90\n"
        assert PasswordMaxDaysCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_exceeding_limit_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/login.defs"] = "PASS_MAX_DAYS\t99999\n"
        assert PasswordMaxDaysCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_never_expires_value_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/login.defs"] = "PASS_MAX_DAYS\t-1\n"
        assert PasswordMaxDaysCheck().audit(make_context(fake_system)).status is Status.FAIL

    def test_non_integer_is_an_error(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/login.defs"] = "PASS_MAX_DAYS\tabc\n"
        assert PasswordMaxDaysCheck().audit(make_context(fake_system)).status is Status.ERROR

    def test_remediation_replaces_the_existing_line(
        self, fake_system: FakeSystem, make_context
    ) -> None:
        fake_system.files["/etc/login.defs"] = "UID_MIN\t1000\nPASS_MAX_DAYS\t99999\n"
        PasswordMaxDaysCheck().remediate(make_context(fake_system))
        content = fake_system.files["/etc/login.defs"]
        assert "PASS_MAX_DAYS\t365" in content
        assert "99999" not in content
        assert "UID_MIN\t1000" in content


class TestSystemAccountShells:
    def test_service_account_with_shell_fails(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = (
            "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/bin/bash\n"
        )
        fake_system.files["/etc/login.defs"] = "UID_MIN\t1000\n"
        result = SystemAccountShellCheck().audit(make_context(fake_system))
        assert result.status is Status.FAIL
        assert "www-data" in result.detail

    def test_nologin_service_accounts_pass(self, fake_system: FakeSystem, make_context) -> None:
        fake_system.files["/etc/passwd"] = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"
            "daemon:x:1:1::/usr/sbin:/bin/false\n"
        )
        fake_system.files["/etc/login.defs"] = "UID_MIN\t1000\n"
        assert SystemAccountShellCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_regular_users_are_not_inspected(self, fake_system: FakeSystem, make_context) -> None:
        """A human at UID 1000 is supposed to have a shell."""
        fake_system.files["/etc/passwd"] = (
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
        )
        fake_system.files["/etc/login.defs"] = "UID_MIN\t1000\n"
        assert SystemAccountShellCheck().audit(make_context(fake_system)).status is Status.PASS

    def test_uid_min_is_read_from_login_defs(self, fake_system: FakeSystem, make_context) -> None:
        """A host with UID_MIN 500 must classify UID 600 as a regular user."""
        fake_system.files["/etc/passwd"] = (
            "root:x:0:0:root:/root:/bin/bash\nsvc:x:600:600::/home/svc:/bin/bash\n"
        )
        fake_system.files["/etc/login.defs"] = "UID_MIN\t500\n"
        result = SystemAccountShellCheck().audit(make_context(fake_system))
        assert result.status is Status.PASS
        assert result.evidence["uid_min"] == 500
