#!/usr/bin/env python3
"""
YARA Rule Generator - Generate YARA rules from malware samples

Features:
- Automatic string extraction
- Signature generation
- Import detection
- Hex pattern extraction
- Entropy-based filtering
- Rule validation
- Batch processing
- Template support
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


@dataclass
class ExtractedString:
    value: str
    offset: int
    string_type: str  # ascii, wide, hex
    entropy: float
    unique: bool = True


@dataclass 
class YARARule:
    name: str
    meta: Dict
    strings: List[Dict]
    condition: str


class YARAGenerator:
    def __init__(
        self,
        min_string_length: int = 6,
        max_strings: int = 20,
        min_entropy: float = 2.0,
        max_entropy: float = 6.0
    ):
        self.min_string_length = min_string_length
        self.max_strings = max_strings
        self.min_entropy = min_entropy
        self.max_entropy = max_entropy
        
        # Common strings to exclude
        self.common_strings = {
            'http://', 'https://', '.com', '.exe', '.dll', '.sys',
            'Microsoft', 'Windows', 'Copyright', 'Version',
            'kernel32', 'ntdll', 'user32', 'advapi32',
            'GetProcAddress', 'LoadLibrary', 'VirtualAlloc',
            'This program', 'DOS mode', 'PE\x00\x00'
        }
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        freq = Counter(data)
        length = len(data)
        entropy = 0.0
        
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.bit_length() - 1) if p > 0 else 0
        
        import math
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def extract_ascii_strings(self, data: bytes) -> List[ExtractedString]:
        """Extract ASCII strings from binary data"""
        strings = []
        pattern = rb'[\x20-\x7e]{%d,}' % self.min_string_length
        
        for match in re.finditer(pattern, data):
            value = match.group().decode('ascii', errors='ignore')
            
            # Skip common strings
            if any(common.lower() in value.lower() for common in self.common_strings):
                continue
            
            entropy = self.calculate_entropy(match.group())
            
            if self.min_entropy <= entropy <= self.max_entropy:
                strings.append(ExtractedString(
                    value=value,
                    offset=match.start(),
                    string_type='ascii',
                    entropy=round(entropy, 2)
                ))
        
        return strings
    
    def extract_wide_strings(self, data: bytes) -> List[ExtractedString]:
        """Extract wide (Unicode) strings"""
        strings = []
        # Wide string pattern (ASCII with null bytes between)
        pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % self.min_string_length
        
        for match in re.finditer(pattern, data):
            try:
                value = match.group().decode('utf-16-le', errors='ignore')
                
                if any(common.lower() in value.lower() for common in self.common_strings):
                    continue
                
                entropy = self.calculate_entropy(value.encode())
                
                if self.min_entropy <= entropy <= self.max_entropy:
                    strings.append(ExtractedString(
                        value=value,
                        offset=match.start(),
                        string_type='wide',
                        entropy=round(entropy, 2)
                    ))
            except:
                continue
        
        return strings
    
    def extract_hex_patterns(self, data: bytes) -> List[ExtractedString]:
        """Extract interesting hex patterns"""
        patterns = []
        
        # PE header patterns
        if b'MZ' in data[:2]:
            patterns.append(ExtractedString(
                value='4D 5A',
                offset=0,
                string_type='hex',
                entropy=0
            ))
        
        # Find repeated byte sequences (potential encoded data)
        for i in range(0, min(len(data) - 16, 1000), 4):
            chunk = data[i:i+16]
            entropy = self.calculate_entropy(chunk)
            
            # Very high entropy might be encrypted/compressed
            if entropy > 7.5:
                hex_str = ' '.join(f'{b:02X}' for b in chunk[:8])
                patterns.append(ExtractedString(
                    value=hex_str,
                    offset=i,
                    string_type='hex',
                    entropy=round(entropy, 2)
                ))
                break
        
        return patterns[:5]  # Limit hex patterns
    
    def detect_imports(self, data: bytes) -> List[str]:
        """Detect suspicious imports"""
        suspicious_imports = [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtUnmapViewOfSection', 'RtlCreateUserThread',
            'SetWindowsHookEx', 'GetAsyncKeyState', 'RegisterHotKey',
            'CryptEncrypt', 'CryptDecrypt', 'CryptoAPI',
            'InternetOpen', 'HttpSendRequest', 'URLDownloadToFile',
            'RegSetValue', 'RegCreateKey', 'WinExec', 'ShellExecute',
            'CreateService', 'StartService', 'OpenSCManager'
        ]
        
        found = []
        for imp in suspicious_imports:
            if imp.encode() in data or imp.encode('utf-16-le') in data:
                found.append(imp)
        
        return found
    
    def generate_rule(
        self,
        filepath: str,
        rule_name: Optional[str] = None,
        author: str = "YARAGen",
        description: str = ""
    ) -> str:
        """Generate YARA rule from file"""
        
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        data = path.read_bytes()
        
        # Calculate hashes
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        
        # Generate rule name
        if not rule_name:
            rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', path.stem)
            rule_name = f"mal_{rule_name}"
        
        # Extract strings
        ascii_strings = self.extract_ascii_strings(data)
        wide_strings = self.extract_wide_strings(data)
        hex_patterns = self.extract_hex_patterns(data)
        imports = self.detect_imports(data)
        
        # Select best strings (unique, good entropy)
        all_strings = ascii_strings + wide_strings
        
        # Score strings by uniqueness and entropy
        scored_strings = []
        seen_values = set()
        for s in all_strings:
            if s.value not in seen_values:
                seen_values.add(s.value)
                score = s.entropy + (5 if len(s.value) > 15 else 0)
                scored_strings.append((score, s))
        
        scored_strings.sort(reverse=True)
        selected_strings = [s for _, s in scored_strings[:self.max_strings]]
        
        # Build YARA rule
        rule_lines = [
            f'rule {rule_name}',
            '{',
            '    meta:',
            f'        author = "{author}"',
            f'        date = "{datetime.now().strftime("%Y-%m-%d")}"',
            f'        description = "{description or "Auto-generated rule"}"',
            f'        md5 = "{md5}"',
            f'        sha256 = "{sha256}"',
            f'        filesize = "{len(data)}"',
            '',
            '    strings:'
        ]
        
        # Add strings
        string_names = []
        for i, s in enumerate(selected_strings):
            name = f"$s{i}"
            string_names.append(name)
            
            if s.string_type == 'ascii':
                rule_lines.append(f'        {name} = "{self._escape_string(s.value)}"')
            elif s.string_type == 'wide':
                rule_lines.append(f'        {name} = "{self._escape_string(s.value)}" wide')
            elif s.string_type == 'hex':
                rule_lines.append(f'        {name} = {{ {s.value} }}')
        
        # Add hex patterns
        for i, h in enumerate(hex_patterns):
            name = f"$h{i}"
            string_names.append(name)
            rule_lines.append(f'        {name} = {{ {h.value} }}')
        
        # Add import strings
        for i, imp in enumerate(imports[:5]):
            name = f"$api{i}"
            string_names.append(name)
            rule_lines.append(f'        {name} = "{imp}"')
        
        # Build condition
        rule_lines.extend([
            '',
            '    condition:',
        ])
        
        if len(string_names) >= 5:
            # Require majority of strings
            threshold = max(3, len(string_names) // 2)
            rule_lines.append(f'        {threshold} of them')
        elif len(string_names) > 0:
            rule_lines.append(f'        any of them')
        else:
            rule_lines.append(f'        filesize < {len(data) * 2} and filesize > {len(data) // 2}')
        
        rule_lines.append('}')
        
        return '\n'.join(rule_lines)
    
    def _escape_string(self, s: str) -> str:
        """Escape string for YARA"""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    
    def validate_rule(self, rule: str) -> Tuple[bool, str]:
        """Basic validation of YARA rule syntax"""
        # Check basic structure
        if 'rule ' not in rule:
            return False, "Missing 'rule' keyword"
        if 'condition:' not in rule:
            return False, "Missing 'condition' section"
        if rule.count('{') != rule.count('}'):
            return False, "Unbalanced braces"
        
        # Check for empty strings section
        if 'strings:' in rule:
            strings_section = rule.split('strings:')[1].split('condition:')[0]
            if not strings_section.strip():
                return False, "Empty strings section"
        
        return True, "Rule appears valid"


def print_banner():
    print(f"""{Colors.CYAN}
 __   __ _    ____      _    ____            
 \ \ / // \  |  _ \    / \  / ___| ___ _ __  
  \ V // _ \ | |_) |  / _ \| |  _ / _ \ '_ \ 
   | |/ ___ \|  _ <  / ___ \ |_| |  __/ | | |
   |_/_/   \_\_| \_\/_/   \_\____|\___|_| |_|
{Colors.RESET}                                 v{VERSION}
""")


def main():
    parser = argparse.ArgumentParser(description="YARA Rule Generator")
    parser.add_argument("file", nargs="?", help="File to analyze")
    parser.add_argument("-n", "--name", help="Rule name")
    parser.add_argument("-a", "--author", default="YARAGen", help="Author name")
    parser.add_argument("-d", "--description", default="", help="Rule description")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--min-length", type=int, default=6, help="Minimum string length")
    parser.add_argument("--max-strings", type=int, default=20, help="Maximum strings to include")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not args.file:
        # Demo mode
        print(f"{Colors.YELLOW}No file specified. Creating demo rule...{Colors.RESET}\n")
        
        demo_rule = '''rule demo_malware_sample
{
    meta:
        author = "YARAGen"
        date = "2024-01-15"
        description = "Demo rule - Example malware signature"
        
    strings:
        $s0 = "cmd.exe /c" ascii
        $s1 = "powershell -enc" ascii wide
        $s2 = "CreateRemoteThread" ascii
        $s3 = "VirtualAllocEx" ascii
        $h0 = { 4D 5A 90 00 }
        
    condition:
        3 of them
}'''
        print(f"{Colors.CYAN}Generated Demo Rule:{Colors.RESET}")
        print(demo_rule)
        return
    
    generator = YARAGenerator(
        min_string_length=args.min_length,
        max_strings=args.max_strings
    )
    
    try:
        print(f"{Colors.BOLD}Analyzing:{Colors.RESET} {args.file}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        
        rule = generator.generate_rule(
            args.file,
            rule_name=args.name,
            author=args.author,
            description=args.description
        )
        
        # Validate
        is_valid, message = generator.validate_rule(rule)
        if is_valid:
            print(f"{Colors.GREEN}[OK] Rule validation: {message}{Colors.RESET}\n")
        else:
            print(f"{Colors.YELLOW}[!] Rule validation: {message}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Generated Rule:{Colors.RESET}")
        print(rule)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(rule)
            print(f"\n{Colors.GREEN}[OK] Saved to: {args.output}{Colors.RESET}")
            
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
