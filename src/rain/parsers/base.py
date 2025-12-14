"""Base parser interface for SBOM formats."""

from abc import ABC, abstractmethod
from typing import Any

from ..models.domain import ParsedSBOM


class BaseParser(ABC):
    """Abstract base class for SBOM parsers."""
    
    @abstractmethod
    async def parse(self, data: dict[str, Any]) -> ParsedSBOM:
        """
        Parse SBOM data into domain model.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            ParsedSBOM object
            
        Raises:
            ValueError: If data is invalid
        """
        pass
    
    @staticmethod
    @abstractmethod
    def can_parse(data: dict[str, Any]) -> bool:
        """
        Check if this parser can handle the given data.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            True if parser can handle this format
        """
        pass


class ParserError(Exception):
    """Base exception for parser errors."""
    pass
