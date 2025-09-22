#!/usr/bin/env python3
"""
File Processing - CVE Creator Support
Processes uploaded files (PDFs, text documents) for vulnerability information extraction.
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import chainlit as cl
import PyPDF2
import io
import tempfile
import asyncio

logger = logging.getLogger(__name__)


class FileProcessor:
    """
    Processes uploaded files for CVE Creator persona.

    Handles PDF extraction, text file reading, and content preparation
    for vulnerability analysis and CVE description creation.
    """

    def __init__(self) -> None:
        """Initialize file processor - PDF only for CVE Creator."""
        self.supported_types = [
            'application/pdf'
        ]
        # Maximum file size: 10MB for PDF documents
        self.max_file_size_mb = 10
        self.max_file_size_bytes = self.max_file_size_mb * 1024 * 1024
        # Cap PDF pages to avoid extremely large documents
        self.max_pdf_pages = 30

    async def process_attachments(self, message: cl.Message) -> Optional[str]:
        """
        Process file attachments from a Chainlit message.

        Args:
            message: Chainlit message with potential file attachments

        Returns:
            Extracted text content from files, or None if no files/issues
        """
        if not hasattr(message, 'elements') or not message.elements:
            logger.debug("No file attachments found in message")
            return None

        extracted_content = []

        for element in message.elements:
            if hasattr(element, 'type') and element.type == 'file':
                # Check file size first
                file_size = self._get_file_size(element)
                if file_size > self.max_file_size_bytes:
                    file_size_mb = file_size / (1024 * 1024)
                    file_info = f"\n--- File: {element.name} (Too Large) ---\n"
                    extracted_content.append(file_info + f"File size ({file_size_mb:.1f}MB) exceeds the {self.max_file_size_mb}MB limit.\nPlease upload a smaller PDF file containing your vulnerability research or security advisory.\n")
                    logger.warning(f"File too large: {element.name} ({file_size_mb:.1f}MB)")
                    continue

                # Check if file type is supported (PDF only)
                mime_type = getattr(element, 'mime', 'application/octet-stream')
                if mime_type not in self.supported_types:
                    file_info = f"\n--- File: {element.name} (Unsupported Format) ---\n"
                    extracted_content.append(file_info + f"Only PDF files up to {self.max_file_size_mb}MB are supported. Found: {mime_type}\nPlease upload a PDF file containing your vulnerability research, security advisory, or technical documentation.\n")
                    logger.warning(f"Unsupported file type: {element.name} ({mime_type})")
                    continue

                try:
                    content = await self._extract_file_content(element)
                    if content:
                        file_info = f"\n--- File: {element.name} ---\n"
                        extracted_content.append(file_info + content)
                        logger.info(f"Successfully extracted content from {element.name}")
                except Exception as e:
                    logger.error(f"Failed to process file {element.name}: {e}")
                    extracted_content.append(f"\n--- File: {element.name} (Processing Error) ---\nUnable to extract content: {str(e)}\n")

        if extracted_content:
            return "\n".join(extracted_content)
        return None

    async def _extract_file_content(self, file_element: Any) -> Optional[str]:
        """
        Extract text content from a file element.

        Args:
            file_element: Chainlit file element

        Returns:
            Extracted text content or None if extraction fails
        """
        try:
            # Read file content
            if hasattr(file_element, 'content'):
                file_content = file_element.content
            elif hasattr(file_element, 'path'):
                file_content = await asyncio.to_thread(self._read_file_from_path, file_element.path)
            else:
                logger.error(f"Cannot access file content for {file_element.name}")
                return None

            # Determine file type and extract accordingly
            mime_type = getattr(file_element, 'mime', 'application/octet-stream')

            if mime_type == 'application/pdf':
                return await asyncio.to_thread(self._extract_pdf_content, file_content)
            elif mime_type.startswith('text/'):
                return self._extract_text_content(file_content)
            else:
                # Try to treat as text first
                try:
                    decoded_content: str = file_content.decode('utf-8')
                    return decoded_content
                except UnicodeDecodeError:
                    logger.warning(f"Cannot decode {file_element.name} as text")
                    return f"[Binary file - {file_element.name} - unable to extract text content]"

        except Exception as e:
            logger.error(f"Error extracting content from {file_element.name}: {e}")
            return None

    def _extract_pdf_content(self, pdf_content: bytes) -> str:
        """Extract text from PDF content."""
        try:
            if not pdf_content or len(pdf_content) == 0:
                return "[Empty PDF file - no content to extract]"

            pdf_file = io.BytesIO(pdf_content)
            reader = PyPDF2.PdfReader(pdf_file)

            if len(reader.pages) == 0:
                return "[PDF contains no pages]"

            text_content = []
            total_pages = len(reader.pages)
            for page_num, page in enumerate(reader.pages, 1):
                try:
                    page_text = page.extract_text()
                    if page_text and page_text.strip():
                        text_content.append(f"--- Page {page_num} ---\n{page_text.strip()}")
                    else:
                        text_content.append(f"--- Page {page_num} ---\n[Page contains no extractable text]")
                except Exception as page_error:
                    text_content.append(f"--- Page {page_num} ---\n[Error extracting text: {str(page_error)}]")

                if page_num >= self.max_pdf_pages:
                    remaining = max(0, total_pages - self.max_pdf_pages)
                    if remaining > 0:
                        text_content.append(f"\n[Truncated: processed first {self.max_pdf_pages} of {total_pages} pages]")
                    break

            if text_content:
                full_content = "\n\n".join(text_content)
                logger.info(f"Successfully extracted {len(full_content)} characters from {len(reader.pages)} pages")
                return full_content
            else:
                return "[PDF file processed but no text content extracted from any pages]"

        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            # Try alternative approach for corrupted PDFs
            try:
                # Sometimes PyPDF2 fails but the content is still readable as text
                text_attempt = pdf_content.decode('utf-8', errors='ignore')
                if len(text_attempt.strip()) > 50:
                    logger.info("PDF extraction failed, but recovered some text content")
                    return f"[PDF text recovery - may contain formatting artifacts]\n{text_attempt[:2000]}"
            except:
                pass

            return f"[PDF processing error: {str(e)} - File may be corrupted, password-protected, or scanned images]"

    def _extract_text_content(self, text_content: bytes) -> str:
        """Extract content from text files."""
        try:
            # Try UTF-8 first
            return text_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                # Try latin-1 as fallback
                return text_content.decode('latin-1')
            except UnicodeDecodeError:
                return "[Text file with unsupported encoding]"

    def analyze_vulnerability_content(self, content: str) -> Dict[str, Any]:
        """
        Analyze extracted content for vulnerability indicators.

        Args:
            content: Extracted file content

        Returns:
            Analysis results with vulnerability indicators
        """
        content_lower = content.lower()

        # Look for vulnerability indicators
        vulnerability_indicators = {
            'cve_references': self._find_cve_references(content),
            'vulnerability_types': self._identify_vulnerability_types(content_lower),
            'product_information': self._extract_product_info(content),
            'impact_indicators': self._find_impact_indicators(content_lower),
            'attack_vectors': self._identify_attack_vectors(content_lower),
            'severity_indicators': self._find_severity_indicators(content_lower)
        }

        return {
            'content_length': len(content),
            'has_vulnerability_content': any(vulnerability_indicators.values()),
            'indicators': vulnerability_indicators,
            'confidence_score': self._calculate_confidence_score(vulnerability_indicators)
        }

    def _find_cve_references(self, content: str) -> List[str]:
        """Find CVE references in content."""
        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        return list(set(cve_pattern.findall(content)))

    def _identify_vulnerability_types(self, content_lower: str) -> List[str]:
        """Identify vulnerability types mentioned."""
        vuln_types = [
            'sql injection', 'cross-site scripting', 'buffer overflow',
            'authentication bypass', 'privilege escalation', 'remote code execution',
            'denial of service', 'information disclosure', 'path traversal',
            'csrf', 'xxe', 'deserialization', 'race condition'
        ]

        found_types = []
        for vuln_type in vuln_types:
            if vuln_type in content_lower:
                found_types.append(vuln_type)

        return found_types

    def _extract_product_info(self, content: str) -> Dict[str, Any]:
        """Extract product and vendor information."""
        import re

        # Look for version patterns
        version_pattern = re.compile(r'version\s+([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9]+)*)', re.IGNORECASE)
        versions = list(set(version_pattern.findall(content)))

        # Look for common product/vendor patterns
        product_indicators = ['product', 'software', 'application', 'system', 'platform']
        vendor_indicators = ['vendor', 'company', 'developer', 'manufacturer']

        return {
            'versions': versions,
            'product_mentions': len([word for word in product_indicators if word in content.lower()]),
            'vendor_mentions': len([word for word in vendor_indicators if word in content.lower()])
        }

    def _find_impact_indicators(self, content_lower: str) -> List[str]:
        """Find impact-related indicators."""
        impact_terms = [
            'execute arbitrary code', 'remote code execution', 'privilege escalation',
            'data disclosure', 'information leak', 'denial of service',
            'bypass authentication', 'gain access', 'unauthorized'
        ]

        return [term for term in impact_terms if term in content_lower]

    def _identify_attack_vectors(self, content_lower: str) -> List[str]:
        """Identify attack vectors mentioned."""
        attack_vectors = [
            'crafted request', 'malicious input', 'specially crafted',
            'malformed request', 'user input', 'file upload',
            'network request', 'authenticated user', 'remote attacker'
        ]

        return [vector for vector in attack_vectors if vector in content_lower]

    def _find_severity_indicators(self, content_lower: str) -> Dict[str, bool]:
        """Find severity-related indicators."""
        return {
            'critical': any(term in content_lower for term in ['critical', 'severe', 'high risk']),
            'high': any(term in content_lower for term in ['high', 'important', 'significant']),
            'medium': any(term in content_lower for term in ['medium', 'moderate']),
            'low': any(term in content_lower for term in ['low', 'minor', 'informational'])
        }

    def _calculate_confidence_score(self, indicators: Dict[str, Any]) -> int:
        """Calculate confidence score based on found indicators."""
        score = 0

        # CVE references add confidence
        if indicators.get('cve_references'):
            score += 30

        # Vulnerability types add confidence
        vuln_types = indicators.get('vulnerability_types', [])
        score += min(len(vuln_types) * 15, 40)

        # Product information adds confidence
        product_info = indicators.get('product_information', {})
        if product_info.get('versions'):
            score += 20
        if product_info.get('product_mentions', 0) > 0:
            score += 10

        # Impact and attack vectors add confidence
        if indicators.get('impact_indicators'):
            score += 15
        if indicators.get('attack_vectors'):
            score += 10

        return min(score, 100)

    def _read_file_from_path(self, file_path: str) -> bytes:
        """Helper method to read file content from path (for asyncio.to_thread)."""
        with open(file_path, 'rb') as f:
            return f.read()

    def _get_file_size(self, file_element: Any) -> int:
        """
        Get the file size in bytes from a file element.

        Args:
            file_element: Chainlit file element

        Returns:
            File size in bytes
        """
        try:
            if hasattr(file_element, 'size') and file_element.size is not None:
                return int(file_element.size)
            elif hasattr(file_element, 'content') and file_element.content is not None:
                return len(file_element.content)
            elif hasattr(file_element, 'path') and file_element.path:
                import os
                return os.path.getsize(file_element.path)
            else:
                logger.warning(f"Cannot determine file size for {getattr(file_element, 'name', 'unknown file')}")
                return 0
        except Exception as e:
            logger.error(f"Error getting file size for {getattr(file_element, 'name', 'unknown file')}: {e}")
            return 0
