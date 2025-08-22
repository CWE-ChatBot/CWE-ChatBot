# apps/cwe_ingestion/downloader.py
"""
Secure CWE data downloader module.
Handles downloading and extracting CWE data from MITRE.
"""
import logging
import zipfile
from pathlib import Path
from typing import Optional
import requests
import tempfile
import os

logger = logging.getLogger(__name__)


class CWEDownloader:
    """Secure downloader for CWE data from MITRE."""
    
    def __init__(
        self, 
        source_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        timeout: int = 30,
        verify_ssl: bool = True
    ):
        self.source_url = source_url
        self.schema_url = "https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        logger.info(f"CWEDownloader initialized with URL: {source_url}")
    
    def download_file(self, output_path: str) -> bool:
        """
        Download CWE ZIP file from MITRE.
        
        Args:
            output_path: Path where to save the downloaded file
            
        Returns:
            bool: True if download successful
            
        Raises:
            Exception: If download fails
        """
        try:
            logger.info(f"Downloading CWE data from {self.source_url}")
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            response = requests.get(
                self.source_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                stream=True
            )
            response.raise_for_status()
            
            # Write file in chunks to handle large files
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            logger.info(f"CWE data downloaded successfully to {output_path}")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Download failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Download failed: {e}")
            raise
    
    def _extract_cwe_xml(self, zip_path: str, output_path: str) -> str:
        """Extract CWE XML file from downloaded ZIP archive."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Find XML file in ZIP
                xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
                
                if not xml_files:
                    raise ValueError("No XML file found in ZIP archive")
                
                # Extract first XML file found
                xml_filename = xml_files[0]
                zip_ref.extract(xml_filename, path=output_file.parent)
                
                # Rename to expected output path
                extracted_path = output_file.parent / xml_filename
                if extracted_path != output_file:
                    extracted_path.rename(output_file)
                
                logger.info(f"CWE XML extracted to {output_path}")
                return str(output_path)
                
        except Exception as e:
            logger.error(f"ZIP extraction failed: {e}")
            raise