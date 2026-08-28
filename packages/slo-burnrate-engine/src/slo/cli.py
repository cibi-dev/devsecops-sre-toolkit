"""Command Line Interface for slo-burnrate-engine.

Provides subcommands: calculate, evaluate-burnrate, budget-status, and report
supporting Markdown, OpenMetrics, and JSON output formats.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
import pandas as pd

from slo.burn_rate import BurnRateCalculator, calculate_burn_rate, parse_window_seconds
from slo.error_budget import ErrorBudgetManager, SLODefinition
from slo.multi_window import MultiWindowAlertEngine, get_standard_google_sre_tiers
from slo.reporter import SLOReporter, redact_sensitive_text
from slo.sli_calculator import calculate_event_sli, calculate_timeseries_sli


def safe_resolve_path(path_str: str) -> str:
    """Sanitize and safely resolve input file path (CWE-22)."""
    clean_path = os.path.expanduser(os.path.expandvars(path_str))
    abs_path = os.path.realpath(clean_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Specified file does not exist: {path_str}")
    if not os.path.isfile(abs_path):
        raise ValueError(f"Path is not a regular file: {path_str}")
    return abs_path


def load_dataset(file_path: str, max_memory_mb: float = 256.0) -> pd.DataFrame:
    """Safely load CSV or JSON dataset into a pandas DataFrame (CWE-20 & CWE-400)."""
    resolved = safe_resolve_path(file_path)
    file_size_mb = os.path.getsize(resolved) / (1024.0 * 1024.0)
    if file_size_mb > max_memory_mb:
        raise ValueError(
            f"File size ({file_size_mb:.2f} MB) exceeds safety threshold of {max_memory_mb:.2f} MB"
        )

    if resolved.endswith(".csv"):
        return pd.read_csv(resolved)
    elif resolved.endswith(".json"):
        return pd.read_json(resolved)
    else:
        # Attempt JSON or CSV fallback
        try:
            return pd.read_json(resolved)
        except Exception:
            return pd.read_csv(resolved)


def cmd_calculate(args: argparse.Namespace) -> int:
    """Handle 'calculate' subcommand."""
    target_slo = float(args.slo)
    service = str(args.service)
    slo_name = str(args.name)

    if args.file:
        df = load_dataset(args.file)
        sli_res = calculate_timeseries_sli(
            data=df,
            good_col=args.good_col,
            total_col=args.total_col,
            bad_col=args.bad_col if hasattr(args, "bad_col") else None,
        )
        good = sli_res.good_events
        total = sli_res.total_events
    else:
        if args.good is None or args.total is None:
            sys.stderr.write("Error: Either --file or both --good and --total must be provided.\n")
            return 1
        good = int(args.good)
        total = int(args.total)
        sli_res = calculate_event_sli(good, total)

    slo_def = SLODefinition(name=slo_name, service=service, target=target_slo)
    eb_mgr = ErrorBudgetManager(slo_def)
    eb_res = eb_mgr.calculate_from_sli(sli_res)

    if args.format == "json":
        out = json.dumps(
            {
                "sli": sli_res.model_dump(),
                "error_budget": eb_res.model_dump(),
            },
            indent=2,
        )
    else:
        out = (
            f"=== SLO & SLI Calculation ===\n"
            f"Service:             {service}\n"
            f"SLO Target:          {target_slo * 100:.3f}%\n"
            f"Total Events:        {total:,}\n"
            f"Good Events:         {good:,}\n"
            f"Bad Events:          {eb_res.bad_events:,}\n"
            f"SLI Compliance:      {sli_res.sli_percent:.4f}%\n"
            f"Error Budget Events: {eb_res.total_budget_events:,.1f}\n"
            f"Budget Consumed:     {eb_res.consumed_budget_percent:.2f}%\n"
            f"Budget Remaining:    {eb_res.remaining_budget_percent:.2f}%\n"
            f"Exhausted:           {'YES 🔴' if eb_res.is_exhausted else 'NO 🟢'}\n"
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_evaluate_burnrate(args: argparse.Namespace) -> int:
    """Handle 'evaluate-burnrate' subcommand."""
    target_slo = float(args.slo)
    good = int(args.good)
    total = int(args.total)
    window = str(args.window)
    remaining_ratio = float(args.remaining_ratio) if args.remaining_ratio is not None else 1.0

    br_res = calculate_burn_rate(
        good_events=good,
        total_events=total,
        target_slo=target_slo,
        window=window,
        remaining_budget_ratio=remaining_ratio,
    )

    if args.format == "json":
        out = json.dumps(br_res.model_dump(), indent=2)
    else:
        tte_str = (
            f"{br_res.time_to_exhaustion_hours:.2f} hours ({br_res.time_to_exhaustion_days:.2f} days)"
            if br_res.time_to_exhaustion_hours is not None
            else "Infinite (0 bad events)"
        )
        out = (
            f"=== Burn Rate Evaluation ===\n"
            f"SLO Target:            {target_slo * 100:.3f}%\n"
            f"Window:                {br_res.window_label} ({br_res.window_seconds:.0f}s)\n"
            f"Observed Error Rate:   {br_res.observed_error_rate * 100:.4f}%\n"
            f"Allowed Error Rate:    {br_res.allowed_error_rate * 100:.4f}%\n"
            f"Burn Rate:             {br_res.burn_rate:.2f}x\n"
            f"Budget Consumed in W:  {br_res.budget_consumed_in_window_percent:.3f}%\n"
            f"Time-to-Exhaustion:    {tte_str}\n"
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_budget_status(args: argparse.Namespace) -> int:
    """Handle 'budget-status' subcommand."""
    target_slo = float(args.slo)
    service = str(args.service)
    slo_name = str(args.name)

    if args.file:
        df = load_dataset(args.file)
        sli_res = calculate_timeseries_sli(
            data=df,
            good_col=args.good_col,
            total_col=args.total_col,
        )
    else:
        if args.good is None or args.total is None:
            sys.stderr.write("Error: Either --file or both --good and --total must be provided.\n")
            return 1
        sli_res = calculate_event_sli(int(args.good), int(args.total))

    slo_def = SLODefinition(name=slo_name, service=service, target=target_slo)
    eb_mgr = ErrorBudgetManager(slo_def)
    eb_res = eb_mgr.calculate_from_sli(sli_res)

    # Compute instantaneous 1h burn rate based on current error rate
    br_calc = BurnRateCalculator(target_slo=target_slo)
    br_res = br_calc.calculate(
        good_events=sli_res.good_events,
        total_events=sli_res.total_events,
        window="1h",
        remaining_budget_ratio=eb_res.remaining_budget_ratio,
    )

    if args.format == "json":
        out = json.dumps(
            {
                "error_budget": eb_res.model_dump(),
                "current_burn_rate": br_res.model_dump(),
            },
            indent=2,
        )
    else:
        status_label = "EXHAUSTED 🔴" if eb_res.is_exhausted else (
            "AT RISK 🟡" if eb_res.remaining_budget_percent < 20 else "HEALTHY 🟢"
        )
        tte_str = (
            f"{br_res.time_to_exhaustion_hours:.1f} hours ({br_res.time_to_exhaustion_days:.2f} days)"
            if br_res.time_to_exhaustion_hours is not None
            else "Infinite"
        )
        out = (
            f"=== 30-Day Error Budget Status ===\n"
            f"Service:               {service}\n"
            f"SLO Target:            {target_slo * 100:.3f}%\n"
            f"Health Status:         {status_label}\n"
            f"Total Requests:        {eb_res.total_events:,}\n"
            f"Allowed Errors:        {eb_res.total_budget_events:,.0f}\n"
            f"Observed Errors:       {eb_res.bad_events:,}\n"
            f"Consumed Budget:       {eb_res.consumed_budget_percent:.2f}%\n"
            f"Remaining Budget:      {eb_res.remaining_budget_percent:.2f}%\n"
            f"Current Burn Rate:     {br_res.burn_rate:.2f}x\n"
            f"Time-to-Exhaustion:    {tte_str}\n"
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Handle 'report' subcommand."""
    target_slo = float(args.slo)
    service = str(args.service)
    slo_name = str(args.name)

    if args.file:
        df = load_dataset(args.file)
        sli_res = calculate_timeseries_sli(
            data=df,
            good_col=args.good_col,
            total_col=args.total_col,
        )
        good = sli_res.good_events
        total = sli_res.total_events
    else:
        good = int(args.good) if args.good is not None else 99900
        total = int(args.total) if args.total is not None else 100000

    slo_def = SLODefinition(name=slo_name, service=service, target=target_slo)
    eb_mgr = ErrorBudgetManager(slo_def)
    eb_res = eb_mgr.calculate_from_events(good, total)

    # Windows to evaluate
    windows = ["5m", "30m", "1h", "6h", "24h"]
    burn_rates = []
    for w in windows:
        br = calculate_burn_rate(
            good_events=good,
            total_events=total,
            target_slo=target_slo,
            window=w,
            remaining_budget_ratio=eb_res.remaining_budget_ratio,
        )
        burn_rates.append(br)

    # Evaluate multi-window alerts
    mw_engine = MultiWindowAlertEngine(slo_def)
    br_dict: dict[str | float, float] = {br.window_label: br.burn_rate for br in burn_rates}
    alert_result = mw_engine.evaluate_from_burn_rates(br_dict)

    reporter = SLOReporter(
        error_budget=eb_res,
        burn_rates=burn_rates,
        alerts=alert_result,
    )

    fmt = args.format.lower()
    if fmt == "markdown" or fmt == "md":
        output_text = reporter.to_markdown()
    elif fmt == "openmetrics" or fmt == "prometheus":
        output_text = reporter.to_openmetrics()
    elif fmt == "json":
        output_text = reporter.to_json()
    else:
        sys.stderr.write(f"Error: Unknown format '{args.format}'. Use markdown, openmetrics, or json.\n")
        return 1

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
    else:
        sys.stdout.write(output_text + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="slo-engine",
        description="Enterprise quantitative SRE engine for Google SRE Multi-Window Multi-Burn-Rate alerting and Error Budgets.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. calculate
    p_calc = subparsers.add_parser("calculate", help="Calculate SLI and Error Budget metrics")
    p_calc.add_argument("--slo", type=float, default=0.999, help="Target SLO (default: 0.999)")
    p_calc.add_argument("--service", type=str, default="api-gateway", help="Service name")
    p_calc.add_argument("--name", type=str, default="availability-slo", help="SLO name")
    p_calc.add_argument("--good", type=int, help="Good events count")
    p_calc.add_argument("--total", type=int, help="Total events count")
    p_calc.add_argument("--file", type=str, help="Path to CSV/JSON dataset")
    p_calc.add_argument("--good-col", type=str, default="good_events", help="Good events column name")
    p_calc.add_argument("--total-col", type=str, default="total_events", help="Total events column name")
    p_calc.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_calc.add_argument("--output", "-o", type=str, help="Output file path")

    # 2. evaluate-burnrate
    p_br = subparsers.add_parser("evaluate-burnrate", help="Evaluate burn rate for specific time windows")
    p_br.add_argument("--slo", type=float, default=0.999, help="Target SLO (default: 0.999)")
    p_br.add_argument("--good", type=int, required=True, help="Good events in window")
    p_br.add_argument("--total", type=int, required=True, help="Total events in window")
    p_br.add_argument("--window", type=str, default="1h", help="Window duration (e.g., 5m, 1h, 6h)")
    p_br.add_argument("--remaining-ratio", type=float, default=1.0, help="Remaining budget ratio (0.0 - 1.0)")
    p_br.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_br.add_argument("--output", "-o", type=str, help="Output file path")

    # 3. budget-status
    p_stat = subparsers.add_parser("budget-status", help="Get 30-day rolling Error Budget health status")
    p_stat.add_argument("--slo", type=float, default=0.999, help="Target SLO (default: 0.999)")
    p_stat.add_argument("--service", type=str, default="payment-service", help="Service name")
    p_stat.add_argument("--name", type=str, default="payment-availability", help="SLO name")
    p_stat.add_argument("--good", type=int, help="Good events count")
    p_stat.add_argument("--total", type=int, help="Total events count")
    p_stat.add_argument("--file", type=str, help="Path to CSV/JSON dataset")
    p_stat.add_argument("--good-col", type=str, default="good_events", help="Good events column name")
    p_stat.add_argument("--total-col", type=str, default="total_events", help="Total events column name")
    p_stat.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_stat.add_argument("--output", "-o", type=str, help="Output file path")

    # 4. report
    p_rep = subparsers.add_parser("report", help="Generate executive Markdown, OpenMetrics, or JSON report")
    p_rep.add_argument("--slo", type=float, default=0.999, help="Target SLO (default: 0.999)")
    p_rep.add_argument("--service", type=str, default="checkout-service", help="Service name")
    p_rep.add_argument("--name", type=str, default="checkout-availability", help="SLO name")
    p_rep.add_argument("--good", type=int, help="Good events count")
    p_rep.add_argument("--total", type=int, help="Total events count")
    p_rep.add_argument("--file", type=str, help="Path to CSV/JSON dataset")
    p_rep.add_argument("--good-col", type=str, default="good_events", help="Good events column name")
    p_rep.add_argument("--total-col", type=str, default="total_events", help="Total events column name")
    p_rep.add_argument("--format", choices=["markdown", "openmetrics", "json"], default="markdown", help="Output report format")
    p_rep.add_argument("--output", "-o", type=str, help="Output file path")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    try:
        if args.subcommand == "calculate":
            return cmd_calculate(args)
        elif args.subcommand == "evaluate-burnrate":
            return cmd_evaluate_burnrate(args)
        elif args.subcommand == "budget-status":
            return cmd_budget_status(args)
        elif args.subcommand == "report":
            return cmd_report(args)
        else:
            parser.print_help()
            return 1
    except Exception as exc:
        sys.stderr.write(f"Error: {redact_sensitive_text(str(exc))}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
