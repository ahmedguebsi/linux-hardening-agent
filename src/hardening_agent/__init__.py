"""Linux hardening, remediation and observability agent.

A dependency-free Python agent that audits a Linux host against a CIS-derived
baseline, optionally remediates findings with backup and rollback, and publishes
the result as Prometheus metrics via a textfile collector and an HTTP exporter.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
