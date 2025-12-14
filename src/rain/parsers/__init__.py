"""Parser module for SBOM formats."""

from typing import Any

from .base import BaseParser, ParserError
from .cyclonedx import CycloneDXParser

__all__ = ["get_parser", "ParserError", "BaseParser"]


def get_parser(data: dict[str, Any]) -> BaseParser:
    """
    Get appropriate parser for SBOM data.
    
    Args:
        data: Parsed JSON data
        
    Returns:
        Parser instance
        
    Raises:
        ParserError: If no parser found for format
    """
    parsers: list[type[BaseParser]] = [
        CycloneDXParser,
        # SPDXParser will go here later
    ]
    
    for parser_class in parsers:
        if parser_class.can_parse(data):
            return parser_class()
    
    raise ParserError(
        "Unknown SBOM format. Supported formats: CycloneDX, SPDX"
    )
