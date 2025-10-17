import os
import json
from pathlib import Path

class Config:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.payloads_dir = self.base_dir / "payloads"
        self.results_dir = self.base_dir / "results"
        self.scans_dir = self.results_dir / "scans"
        self.reports_dir = self.results_dir / "reports"
        
        # Create directories
        self.results_dir.mkdir(exist_ok=True)
        self.scans_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        
        # Scanner settings
        self.timeout = 15
        self.delay = 0.5
        self.max_workers = 3
        self.retry_count = 2
        
        # Enhanced detection settings
        self.detection_strings = ["XSS", "xss", "alert", "confirm", "prompt", "document.cookie"]
        
        # Browser settings
        self.headless = True
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def get_payloads(self, category="all"):
        """Load payloads from organized files"""
        payloads = []
        
        # Define payload files to load based on category
        if category == "all":
            files_to_load = ["basic.txt", "advanced.txt", "polyglot.txt"]
        else:
            files_to_load = [f"{category}.txt"]
        
        for filename in files_to_load:
            file_path = self.payloads_dir / filename
            if file_path.exists():
                payloads.extend(self._load_payload_file(file_path))
        
        return list(set(payloads))  # Remove duplicates

    def _load_payload_file(self, file_path):
        """Load and validate payloads from file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"[!] Error loading payloads from {file_path}: {e}")
            return []

config = Config()