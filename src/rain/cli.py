"""Command-line interface for RAIN SBOM."""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .db.session import get_session_factory, init_db, get_db_path
from .models.domain import ParsedSBOM
from .parsers import ParserError, get_parser
from .services.sbom_service import SBOMService

# Setup logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s"
)
logger = logging.getLogger(__name__)


def print_summary(sbom: ParsedSBOM) -> None:
    """Print human-readable summary."""
    print("🌧️  Parsing SBOM...")
    print(f"✅ Format: {sbom.format.upper()} {sbom.spec_version}")
    print(f"📦 Name: {sbom.name}")
    if sbom.version:
        print(f"📌 Version: {sbom.version}")
    
    summary = sbom.summary()
    print(f"\n📊 Components: {summary['total_components']}")
    
    if summary['licenses']:
        print("\n📋 Licenses:")
        for license_id, count in sorted(
            summary['licenses'].items(), 
            key=lambda x: x[1], 
            reverse=True
        ):
            print(f"   - {license_id}: {count}")
    
    if summary['vulnerabilities']:
        total_vulns = sum(summary['vulnerabilities'].values())
        print(f"\n🛡️  Vulnerabilities: {total_vulns} found")
        for severity, count in sorted(summary['vulnerabilities'].items()):
            emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }.get(severity.upper(), "⚪")
            print(f"   {emoji} {severity}: {count}")
        
        # Show first 3 vulnerabilities
        for vuln in sbom.vulnerabilities[:3]:
            print(f"      - {vuln.id} ({vuln.severity or 'UNKNOWN'})")
            if vuln.affected_component:
                print(f"        in {vuln.affected_component}")


def print_json(sbom: ParsedSBOM) -> None:
    """Print JSON output."""
    output = {
        "name": sbom.name,
        "version": sbom.version,
        "format": sbom.format,
        "spec_version": sbom.spec_version,
        "components": [
            {
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "type": c.type,
                "license": c.license_id,
                "supplier": c.supplier,
                "hashes": c.hashes,
            }
            for c in sbom.components
        ],
        "vulnerabilities": [
            {
                "id": v.id,
                "severity": v.severity,
                "description": v.description,
                "affected": v.affected_component,
            }
            for v in sbom.vulnerabilities
        ],
        "summary": sbom.summary(),
        "metadata": sbom.metadata,
    }
    print(json.dumps(output, indent=2))


async def parse_command(args: argparse.Namespace) -> int:
    """Handle parse command."""
    file_path = Path(args.file)
    
    # Check file exists
    if not file_path.exists():
        print(f"❌ Error: File not found: {file_path}", file=sys.stderr)
        return 1
    
    # Read file
    try:
        file_content = "" # Initialize
        with open(file_path) as f:
            file_content = f.read() # Save for later
        data = json.loads(file_content)
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Error reading file: {e}", file=sys.stderr)
        return 1

    # Parse SBOM
    try:
        parser = get_parser(data)
        sbom = await parser.parse(data)
    except ParserError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # Output results
    if args.json:
        print_json(sbom)
    else:
        print_summary(sbom)

    # Save to file if requested
    if args.output:
        output_path = Path(args.output)
        try:
            with open(output_path, 'w') as f:
                json.dump({
                    "name": sbom.name,
                    "version": sbom.version,
                    "format": sbom.format,
                    "components": [
                        {"name": c.name, "version": c.version, "license": c.license_id}
                        for c in sbom.components
                    ],
                    "summary": sbom.summary(),
                }, f, indent=2)
            print(f"\n💾 Saved to: {output_path}")
        except Exception as e:
            print(f"❌ Error saving file: {e}", file=sys.stderr)
            return 1

    # Save to database if requested
    if args.save:
        print("\n⚠️  Database storage not yet implemented")
        print("   (Coming soon!)")
        try:
            # Initialize database
            await init_db()

            # Get session and service
            session_factory = get_session_factory()
            async with session_factory() as session:
                service = SBOMService(session)

                # Save to database
                db_sbom = await service.save_from_file(
                    file_content,
                    name=args.name
                )

                print(f"\n💾 Saved to database (ID: {db_sbom.id})")
                print(f"📁 Database: {get_db_path()}")

        except Exception as e:
            print(f"❌ Error saving to database: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    return 0

async def list_command(args: argparse.Namespace) -> int:
    """Handle list command."""
    try:
        # Initialize database
        await init_db()

        # Get session and service
        session_factory = get_session_factory()
        async with session_factory() as session:
            service = SBOMService(session)

            # List SBOMs
            sboms = await service.list_all(limit=args.limit)
            total = await service.count()

            if not sboms:
                print("No SBOMs in database")
                print(f"\n📁 Database: {get_db_path()}")
                return 0

            # Print table
            print(f"{'ID':<5} {'Name':<30} {'Format':<12} {'Components':<12} {'Date':<20}")
            print("-" * 80)

            for sbom in sboms:
                comp_count = len(sbom.components)
                date_str = sbom.uploaded_at.strftime("%Y-%m-%d %H:%M")
                print(f"{sbom.id:<5} {sbom.name[:28]:<30} {sbom.format:<12} {comp_count:<12} {date_str:<20}")

            print(f"\nTotal: {total} SBOMs")
            print(f"📁 Database: {get_db_path()}")

    except Exception as e:
        print(f"❌ Error listing SBOMs: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    return 0

def server_command(args: argparse.Namespace) -> int:
    """Handle server command."""
    import uvicorn

    print("🌧️  Starting RAIN SBOM API server...")
    print(f"📡 Host: {args.host}")
    print(f"🔌 Port: {args.port}")
    print(f"🔄 Reload: {args.reload}")
    print("\n🌐 API Documentation:")
    print(f"   Swagger UI: http://{args.host}:{args.port}/docs")
    print(f"   ReDoc:      http://{args.host}:{args.port}/redoc")
    print("\nPress CTRL+C to stop\n")

    uvicorn.run(
        "rain.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level
    )

    return 0

def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m rain",
        description="🌧️ RAIN - SBOM Parser and Comparator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m rain parse sbom.json
  python -m rain parse sbom.json --json
  python -m rain parse sbom.json --output parsed.json
  python -m rain parse sbom.json --save --name "Production v1.0"
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Parse command
    parse_parser = subparsers.add_parser(
        "parse",
        help="Parse an SBOM file"
    )
    parse_parser.add_argument(
        "file",
        help="Path to SBOM file (JSON)"
    )
    parse_parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON instead of summary"
    )
    parse_parser.add_argument(
        "--output", "-o",
        help="Save parsed output to file"
    )
    parse_parser.add_argument(
        "--save",
        action="store_true",
        help="Save to database (requires --name)"
    )
    parse_parser.add_argument(
        "--name",
        help="Name for saved SBOM (used with --save)"
    )
    parse_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (show warnings)"
    )
    
    # List command
    list_parser = subparsers.add_parser(
        "list",
        help="List stored SBOMs"
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number to show (default: 100)"
    )
    list_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )

    # Server command
    server_parser = subparsers.add_parser(
        "server",
        help="Start FastAPI server"
    )
    server_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind (default: 0.0.0.0)"
    )
    server_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind (default: 8000)"
    )
    server_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on code changes"
    )
    server_parser.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug"],
        help="Log level (default: info)"
    )

    args = parser.parse_args()
    
    # Set log level
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    # Handle commands
    if args.command == "parse":
        return asyncio.run(parse_command(args))
    elif args.command == "list":
        return asyncio.run(list_command(args))
    elif args.command == "server":
        return server_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
