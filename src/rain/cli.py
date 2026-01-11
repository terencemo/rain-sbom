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

async def compare_command(args: argparse.Namespace) -> int:
    """Handle compare command."""
    file1_path = Path(args.file1)
    file2_path = Path(args.file2)
    
    # Check files exist
    if not file1_path.exists():
        print(f"❌ Error: File not found: {file1_path}", file=sys.stderr)
        return 1
    if not file2_path.exists():
        print(f"❌ Error: File not found: {file2_path}", file=sys.stderr)
        return 1
    
    try:
        # Initialize database
        await init_db()
        
        # Get session and services
        session_factory = get_session_factory()
        async with session_factory() as session:
            from .services.compare_service import CompareService
            
            sbom_service = SBOMService(session)
            compare_service = CompareService(session)
            
            # Read and parse both files
            with open(file1_path) as f:
                file1_content = f.read()
            with open(file2_path) as f:
                file2_content = f.read()
            
            # Save both to database temporarily
            sbom1 = await sbom_service.save_from_file(
                file1_content,
                name=f"Compare: {file1_path.name}"
            )
            sbom2 = await sbom_service.save_from_file(
                file2_content,
                name=f"Compare: {file2_path.name}"
            )
            
            print(f"Comparing SBOMs...")
            print(f"Baseline:   {sbom1.name} ({sbom1.format} {sbom1.spec_version})")
            print(f"Target:     {sbom2.name} ({sbom2.format} {sbom2.spec_version})")
            print()
            
            # Compare
            result = await compare_service.compare(sbom1.id, sbom2.id)
            
            # Print results
            if args.json:
                print_comparison_json(result)
            else:
                print_comparison_summary(result)
            
            # Clean up temporary SBOMs unless --save flag
            if not args.save:
                await sbom_service.delete(sbom1.id)
                await sbom_service.delete(sbom2.id)
            else:
                print(f"\n💾 Saved to database (IDs: {sbom1.id}, {sbom2.id})")
    
    except Exception as e:
        print(f"❌ Error comparing SBOMs: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


def print_comparison_summary(result) -> None:
    """Print human-readable comparison summary."""
    summary = result.summary
    
    # Summary stats
    print("📊 Summary:")
    print(f"   Components in baseline:  {summary['total_sbom1']}")
    print(f"   Components in target:    {summary['total_sbom2']}")
    print(f"   Added:                   {summary['added']}")
    print(f"   Removed:                 {summary['removed']}")
    print(f"   Changed versions:        {summary['changed']}")
    print(f"   License changes:         {summary['license_changes']}")
    print(f"   Unchanged:               {summary['unchanged']}")
    print()
    
    # Added components
    if result.added_components:
        print(f"✅ Added Components ({len(result.added_components)}):")
        for comp in result.added_components[:10]:  # Show first 10
            version = f"v{comp['version']}" if comp['version'] else "no version"
            license_info = f"({comp['license']})" if comp['license'] else ""
            print(f"   + {comp['name']} {version} {license_info}")
        if len(result.added_components) > 10:
            print(f"   ... and {len(result.added_components) - 10} more")
        print()
    
    # Removed components
    if result.removed_components:
        print(f"❌ Removed Components ({len(result.removed_components)}):")
        for comp in result.removed_components[:10]:
            version = f"v{comp['version']}" if comp['version'] else "no version"
            license_info = f"({comp['license']})" if comp['license'] else ""
            print(f"   - {comp['name']} {version} {license_info}")
        if len(result.removed_components) > 10:
            print(f"   ... and {len(result.removed_components) - 10} more")
        print()
    
    # Changed components
    if result.changed_components:
        print(f"🔄 Version Changes ({len(result.changed_components)}):")
        for change in result.changed_components[:10]:
            old_v = change.old_version or "?"
            new_v = change.new_version or "?"
            print(f"   ~ {change.name}: {old_v} → {new_v}")
        if len(result.changed_components) > 10:
            print(f"   ... and {len(result.changed_components) - 10} more")
        print()
    
    # License changes
    if result.license_changes:
        print(f"⚖️  License Changes ({len(result.license_changes)}):")
        for change in result.license_changes[:10]:
            old_lic = change.old_license or "None"
            new_lic = change.new_license or "None"
            print(f"   ~ {change.name}: {old_lic} → {new_lic}")
        if len(result.license_changes) > 10:
            print(f"   ... and {len(result.license_changes) - 10} more")
        print()
    
    # No changes
    if not result.added_components and not result.removed_components and not result.changed_components:
        print("✨ No differences found - SBOMs are identical")


def print_comparison_json(result) -> None:
    """Print comparison as JSON."""
    import json
    
    output = {
        "sbom1": result.sbom1,
        "sbom2": result.sbom2,
        "added": result.added_components,
        "removed": result.removed_components,
        "changed": [
            {
                "name": c.name,
                "old_version": c.old_version,
                "new_version": c.new_version,
                "old_license": c.old_license,
                "new_license": c.new_license,
            }
            for c in result.changed_components
        ],
        "license_changes": [
            {
                "name": c.name,
                "old_license": c.old_license,
                "new_license": c.new_license,
            }
            for c in result.license_changes
        ],
        "summary": result.summary
    }
    
    print(json.dumps(output, indent=2))

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

    # Compare command
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare two SBOM files"
    )
    compare_parser.add_argument(
        "file1",
        help="First SBOM file (baseline)"
    )
    compare_parser.add_argument(
        "file2",
        help="Second SBOM file (comparison target)"
    )
    compare_parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON instead of summary"
    )
    compare_parser.add_argument(
        "--save",
        action="store_true",
        help="Save both SBOMs to database after comparison"
    )
    compare_parser.add_argument(
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
    elif args.command == "compare":
        return asyncio.run(compare_command(args))
    elif args.command == "server":
        return server_command(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
