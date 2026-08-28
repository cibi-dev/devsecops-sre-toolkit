"""Command-line interface (CLI) for blue-green-deployer.

Provides subcommands:
  deploy    - Execute full zero-downtime Blue/Green deployment cycle
  switch    - Manually switch traffic to specified slot
  rollback  - Rollback traffic to the alternate slot
  status    - Display current active slot and health metrics
  health    - Probe health of Blue, Green, or active environment
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from deployer.config import DeployerConfig, EnvironmentSlot
from deployer.engine import DeployEngine
from deployer.health import HealthChecker


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser with common options across commands."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--config", "-c",
        type=str,
        default=argparse.SUPPRESS,
        help="Path to JSON configuration file",
    )
    common_parser.add_argument(
        "--allow-unprivileged",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Allow running without root privileges (for development/testing)",
    )
    common_parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Output results in JSON format",
    )

    parser = argparse.ArgumentParser(
        prog="blue-green-deployer",
        description="Enterprise Zero-Downtime Blue/Green Deployment Orchestrator for Linux",
        parents=[common_parser],
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="blue-green-deployer 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: deploy
    deploy_p = subparsers.add_parser(
        "deploy",
        help="Run full Blue/Green deployment cycle",
        parents=[common_parser],
    )
    deploy_p.add_argument(
        "--target",
        type=str,
        choices=["blue", "green"],
        default=None,
        help="Target slot to deploy to (defaults to opposite of active slot)",
    )

    # Command: switch
    switch_p = subparsers.add_parser(
        "switch",
        help="Manually switch traffic to a slot",
        parents=[common_parser],
    )
    switch_p.add_argument(
        "--target",
        type=str,
        required=True,
        choices=["blue", "green"],
        help="Target slot to switch to",
    )
    switch_p.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Bypass pre-switch health verification",
    )

    # Command: rollback
    rollback_p = subparsers.add_parser(
        "rollback",
        help="Manually trigger traffic rollback",
        parents=[common_parser],
    )
    rollback_p.add_argument(
        "--reason",
        type=str,
        default="Manual operator rollback from CLI",
        help="Reason for manual rollback",
    )

    # Command: status
    subparsers.add_parser(
        "status",
        help="Inspect current active slot and cluster health",
        parents=[common_parser],
    )

    # Command: health
    health_p = subparsers.add_parser(
        "health",
        help="Probe health of target slot(s)",
        parents=[common_parser],
    )
    health_p.add_argument(
        "--slot",
        type=str,
        choices=["blue", "green", "both", "active"],
        default="both",
        help="Which environment to probe",
    )

    return parser


def load_config(config_path: Optional[str], allow_unprivileged: bool = False) -> DeployerConfig:
    """Load DeployerConfig from file or instantiate default."""
    if config_path:
        cfg = DeployerConfig.from_file(config_path)
    else:
        cfg = DeployerConfig()

    if allow_unprivileged:
        cfg.allow_unprivileged = True
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    is_json = getattr(args, "json", False)

    try:
        config_path = getattr(args, "config", None)
        allow_unprivileged = getattr(args, "allow_unprivileged", False)
        config = load_config(config_path, allow_unprivileged=allow_unprivileged)
        engine = DeployEngine(config=config)

        if args.command == "deploy":
            target_slot = EnvironmentSlot(args.target) if getattr(args, "target", None) else None
            result = engine.deploy(target_slot=target_slot)

            if is_json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                status_symbol = "✅" if result.success else "❌"
                print(f"{status_symbol} Deployment Result: {result.status.value.upper()}")
                print(f"   Duration: {result.total_duration_ms:.1f} ms")
                print(f"   Active Slot: {result.new_active_slot.value.upper() if result.new_active_slot else 'UNKNOWN'}")
                print(f"   Message: {result.message}")

            return 0 if result.success else 1

        elif args.command == "switch":
            target_slot = EnvironmentSlot(args.target)
            force = getattr(args, "force", False)
            result = engine.manual_switch(target_slot=target_slot, skip_health=force)

            if is_json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                status_symbol = "✅" if result.success else "❌"
                print(f"{status_symbol} Switch to {target_slot.value.upper()}: {result.status.value.upper()}")
                print(f"   Message: {result.message}")

            return 0 if result.success else 1

        elif args.command == "rollback":
            reason = getattr(args, "reason", "Manual operator rollback from CLI")
            res = engine.manual_rollback(reason=reason)

            if is_json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                status_symbol = "✅" if res.success else "❌"
                print(f"{status_symbol} Rollback: {'COMPLETED' if res.success else 'FAILED'}")
                print(f"   Restored Slot: {res.restored_slot.value.upper()}")
                print(f"   Rollback Duration: {res.rollback_duration_ms:.2f} ms (<30s SLA)")
                print(f"   Restored Health: {'HEALTHY' if res.restored_health else 'UNHEALTHY'}")

            return 0 if res.success else 1

        elif args.command == "status":
            status_data = engine.get_status()

            if is_json:
                print(json.dumps(status_data, indent=2))
            else:
                print("========================================")
                print("      BLUE/GREEN DEPLOYER STATUS        ")
                print("========================================")
                print(f"Active Slot   : {status_data['active_slot'].upper()}")
                print(f"Passive Slot  : {status_data['passive_slot'].upper()}")
                print(f"Symlink Target: {status_data['symlink_target']}")
                print(f"Lock Held     : {'YES' if status_data['lock_held'] else 'NO'}")
                print("----------------------------------------")
                print(f"BLUE  ({status_data['blue']['url']}): {'HEALTHY ✅' if status_data['blue']['healthy'] else 'DOWN ❌'} ({status_data['blue']['latency_ms']} ms)")
                print(f"GREEN ({status_data['green']['url']}): {'HEALTHY ✅' if status_data['green']['healthy'] else 'DOWN ❌'} ({status_data['green']['latency_ms']} ms)")
                print("========================================")

            return 0

        elif args.command == "health":
            checker = HealthChecker(config=config.health)
            slots_to_check: List[EnvironmentSlot] = []

            slot_arg = getattr(args, "slot", "both")
            if slot_arg == "blue":
                slots_to_check = [EnvironmentSlot.BLUE]
            elif slot_arg == "green":
                slots_to_check = [EnvironmentSlot.GREEN]
            elif slot_arg == "active":
                active = engine.get_current_active_slot() or EnvironmentSlot.BLUE
                slots_to_check = [active]
            else:
                slots_to_check = [EnvironmentSlot.BLUE, EnvironmentSlot.GREEN]

            results = {}
            all_healthy = True

            for s in slots_to_check:
                target_cfg = config.get_slot_config(s)
                h_res = checker.check_target(target_cfg)
                results[s.value] = h_res.to_dict()
                if not h_res.healthy:
                    all_healthy = False

            if is_json:
                print(json.dumps(results, indent=2))
            else:
                for s_name, res_dict in results.items():
                    h_sym = "✅ HEALTHY" if res_dict["healthy"] else "❌ UNHEALTHY"
                    print(f"Slot {s_name.upper()}: {h_sym} ({res_dict['total_duration_ms']} ms) - {res_dict['message']}")

            return 0 if all_healthy else 1

        return 0

    except Exception as exc:
        if is_json:
            print(json.dumps({"error": str(exc), "success": False}, indent=2), file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
