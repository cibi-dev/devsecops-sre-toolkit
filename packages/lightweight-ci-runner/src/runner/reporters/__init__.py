"""
Pipeline reporters for JUnit XML and console rendering.
"""

from runner.reporters.junit import generate_junit_xml
from runner.reporters.console import ConsoleReporter

__all__ = ["generate_junit_xml", "ConsoleReporter"]
