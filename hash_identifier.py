#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Hash Identifier
A modern tool for identifying hash types and cryptographic algorithms
Author: Your Name
GitHub: https://github.com/yourusername/hash-identifier
Version: 2.0.0
"""

import argparse
import sys
import re
from typing import List, Dict, Set
from collections import defaultdict

VERSION = "2.0.0"

# Color codes for terminal output
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    @staticmethod
    def disable():
        """Disable colors"""
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.MAGENTA = ''
        Colors.WHITE = ''
        Colors.GRAY = ''

# ASCII Art Banner
def get_banner():
    return f"""{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   {Colors.BOLD}██╗  ██╗ █████╗ ███████╗██╗  ██╗    ██╗██████╗{Colors.ENDC}{Colors.CYAN}                    ║
║   {Colors.BOLD}██║  ██║██╔══██╗██╔════╝██║  ██║    ██║██╔══██╗{Colors.ENDC}{Colors.CYAN}                   ║
║   {Colors.BOLD}███████║███████║███████╗███████║    ██║██║  ██║{Colors.ENDC}{Colors.CYAN}                   ║
║   {Colors.BOLD}██╔══██║██╔══██║╚════██║██╔══██║    ██║██║  ██║{Colors.ENDC}{Colors.CYAN}                   ║
║   {Colors.BOLD}██║  ██║██║  ██║███████║██║  ██║    ██║██████╔╝{Colors.ENDC}{Colors.CYAN}                   ║
║   {Colors.BOLD}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝╚═════╝{Colors.ENDC}{Colors.CYAN}                    ║
║                                                                       ║
║         {Colors.YELLOW}Enhanced Hash Algorithm Identifier v{VERSION}{Colors.ENDC}{Colors.CYAN}              ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""


class HashIdentifier:
    """Main class for identifying hash algorithms"""
    
    def __init__(self):
        self.hash_patterns = self._initialize_patterns()
        self.confidence_scores = defaultdict(int)
    
    def _initialize_patterns(self) -> Dict[str, Dict]:
        """Initialize hash patterns with metadata"""
        return {
            # CRC & Checksum Algorithms
            "CRC-16": {
                "length": 4,
                "pattern": r"^[a-fA-F0-9]{4}$",
                "charset": "hex",
                "category": "Checksum"
            },
            "CRC-16-CCITT": {
                "length": 4,
                "pattern": r"^[a-fA-F0-9]{4}$",
                "charset": "hex",
                "category": "Checksum"
            },
            "CRC-32": {
                "length": 8,
                "pattern": r"^[a-fA-F0-9]{8}$",
                "charset": "hex",
                "category": "Checksum"
            },
            "CRC-32B": {
                "length": 8,
                "pattern": r"^[a-fA-F0-9]{8}$",
                "charset": "hex",
                "category": "Checksum"
            },
            "ADLER-32": {
                "length": 8,
                "pattern": r"^[a-fA-F0-9]{8}$",
                "charset": "hex",
                "category": "Checksum"
            },
            
            # MD Family
            "MD2": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "MD Family"
            },
            "MD4": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "MD Family"
            },
            "MD5": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "MD Family"
            },
            "MD5(HMAC)": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "MD Family"
            },
            "NTLM": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "Windows"
            },
            "MD5(Unix)": {
                "length": 34,
                "pattern": r"^\$1\$.{8}\$.{22}$",
                "charset": "special",
                "category": "Unix/Linux"
            },
            "MD5(Wordpress)": {
                "length": 34,
                "pattern": r"^\$P\$.{31}$",
                "charset": "special",
                "category": "CMS"
            },
            "MD5(phpBB3)": {
                "length": 34,
                "pattern": r"^\$H\$.{31}$",
                "charset": "special",
                "category": "CMS"
            },
            "MD5(APR)": {
                "length": 37,
                "pattern": r"^\$apr1\$.{8}\$.{22}$",
                "charset": "special",
                "category": "Apache"
            },
            
            # SHA Family
            "SHA-1": {
                "length": 40,
                "pattern": r"^[a-fA-F0-9]{40}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-1(HMAC)": {
                "length": 40,
                "pattern": r"^[a-fA-F0-9]{40}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-1(Django)": {
                "length": 49,
                "pattern": r"^sha1\$.{6}\$.{40}$",
                "charset": "special",
                "category": "Framework"
            },
            "MySQL5": {
                "length": 40,
                "pattern": r"^[a-fA-F0-9]{40}$",
                "charset": "hex",
                "category": "Database"
            },
            "MySQL 160bit": {
                "length": 41,
                "pattern": r"^\*[a-fA-F0-9]{40}$",
                "charset": "special",
                "category": "Database"
            },
            "SHA-224": {
                "length": 56,
                "pattern": r"^[a-fA-F0-9]{56}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-256": {
                "length": 64,
                "pattern": r"^[a-fA-F0-9]{64}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-256(HMAC)": {
                "length": 64,
                "pattern": r"^[a-fA-F0-9]{64}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-256(Unix)": {
                "length": 98,
                "pattern": r"^\$6\$.{8,16}\$.{86}$",
                "charset": "special",
                "category": "Unix/Linux"
            },
            "SHA-256(Django)": {
                "length": 77,
                "pattern": r"^sha256\$.{6}\$.{64}$",
                "charset": "special",
                "category": "Framework"
            },
            "SHA-384": {
                "length": 96,
                "pattern": r"^[a-fA-F0-9]{96}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-384(Django)": {
                "length": 103,
                "pattern": r"^sha384\$.{6}\$.{96}$",
                "charset": "special",
                "category": "Framework"
            },
            "SHA-512": {
                "length": 128,
                "pattern": r"^[a-fA-F0-9]{128}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            "SHA-512(HMAC)": {
                "length": 128,
                "pattern": r"^[a-fA-F0-9]{128}$",
                "charset": "hex",
                "category": "SHA Family"
            },
            
            # Other Algorithms
            "RIPEMD-128": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "RIPEMD Family"
            },
            "RIPEMD-160": {
                "length": 40,
                "pattern": r"^[a-fA-F0-9]{40}$",
                "charset": "hex",
                "category": "RIPEMD Family"
            },
            "RIPEMD-256": {
                "length": 64,
                "pattern": r"^[a-fA-F0-9]{64}$",
                "charset": "hex",
                "category": "RIPEMD Family"
            },
            "RIPEMD-320": {
                "length": 80,
                "pattern": r"^[a-fA-F0-9]{80}$",
                "charset": "hex",
                "category": "RIPEMD Family"
            },
            "Whirlpool": {
                "length": 128,
                "pattern": r"^[a-fA-F0-9]{128}$",
                "charset": "hex",
                "category": "Advanced"
            },
            "Tiger-128": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "Tiger Family"
            },
            "Tiger-160": {
                "length": 40,
                "pattern": r"^[a-fA-F0-9]{40}$",
                "charset": "hex",
                "category": "Tiger Family"
            },
            "Tiger-192": {
                "length": 48,
                "pattern": r"^[a-fA-F0-9]{48}$",
                "charset": "hex",
                "category": "Tiger Family"
            },
            "Haval-128": {
                "length": 32,
                "pattern": r"^[a-fA-F0-9]{32}$",
                "charset": "hex",
                "category": "Haval Family"
            },
            "Haval-160": {
                "length": 40,
                "pattern": r"^[a-fA-F0-9]{40}$",
                "charset": "hex",
                "category": "Haval Family"
            },
            "Haval-192": {
                "length": 48,
                "pattern": r"^[a-fA-F0-9]{48}$",
                "charset": "hex",
                "category": "Haval Family"
            },
            "Haval-224": {
                "length": 56,
                "pattern": r"^[a-fA-F0-9]{56}$",
                "charset": "hex",
                "category": "Haval Family"
            },
            "Haval-256": {
                "length": 64,
                "pattern": r"^[a-fA-F0-9]{64}$",
                "charset": "hex",
                "category": "Haval Family"
            },
            "DES(Unix)": {
                "length": 13,
                "pattern": r"^[./0-9A-Za-z]{13}$",
                "charset": "special",
                "category": "Unix/Linux"
            },
            "Joomla": {
                "length": 49,
                "pattern": r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16}$",
                "charset": "special",
                "category": "CMS"
            },
            "SAM(LM_Hash:NT_Hash)": {
                "length": 65,
                "pattern": r"^[A-F0-9]{32}:[A-F0-9]{32}$",
                "charset": "special",
                "category": "Windows"
            },
        }
    
    def identify(self, hash_string: str) -> List[Dict]:
        """
        Identify possible hash types for the given hash string
        
        Args:
            hash_string: The hash to identify
            
        Returns:
            List of dictionaries containing hash type information
        """
        hash_string = hash_string.strip()
        matches = []
        
        for hash_type, properties in self.hash_patterns.items():
            if self._matches_pattern(hash_string, properties):
                confidence = self._calculate_confidence(hash_string, properties)
                matches.append({
                    "type": hash_type,
                    "category": properties["category"],
                    "confidence": confidence,
                    "length": len(hash_string)
                })
        
        # Sort by confidence score (highest first)
        matches.sort(key=lambda x: x["confidence"], reverse=True)
        return matches
    
    def _matches_pattern(self, hash_string: str, properties: Dict) -> bool:
        """Check if hash matches the pattern"""
        if len(hash_string) != properties["length"]:
            return False
        
        pattern = properties["pattern"]
        return bool(re.match(pattern, hash_string))
    
    def _calculate_confidence(self, hash_string: str, properties: Dict) -> int:
        """Calculate confidence score for a match"""
        confidence = 50  # Base confidence
        
        # Increase confidence for specific patterns
        if properties["charset"] == "special":
            confidence += 30  # Special format patterns are more specific
        
        # Analyze character distribution for hex strings
        if properties["charset"] == "hex":
            if self._has_good_entropy(hash_string):
                confidence += 20
        
        return min(confidence, 100)
    
    def _has_good_entropy(self, hash_string: str) -> bool:
        """Check if hash has good character distribution"""
        char_count = defaultdict(int)
        for char in hash_string.lower():
            char_count[char] += 1
        
        # Check if distribution is relatively uniform
        avg_count = len(hash_string) / len(char_count)
        variance = sum((count - avg_count) ** 2 for count in char_count.values()) / len(char_count)
        
        return variance < avg_count * 2


def get_confidence_bar(confidence: int, width: int = 20) -> str:
    """Generate a visual confidence bar"""
    filled = int((confidence / 100) * width)
    bar = '█' * filled + '░' * (width - filled)
    
    if confidence >= 70:
        color = Colors.GREEN
    elif confidence >= 50:
        color = Colors.YELLOW
    else:
        color = Colors.RED
    
    return f"{color}{bar}{Colors.ENDC}"


def display_results(results: List[Dict], hash_string: str, verbose: bool = False):
    """Display identification results"""
    if not results:
        print(f"\n{Colors.RED}[!] No hash type identified{Colors.ENDC}")
        print(f"    {Colors.GRAY}Hash length: {len(hash_string)} characters{Colors.ENDC}")
        return
    
    print(f"\n{Colors.CYAN}[*] Analyzing hash:{Colors.ENDC} {Colors.WHITE}{hash_string[:50]}{'...' if len(hash_string) > 50 else ''}{Colors.ENDC}")
    print(f"    {Colors.GRAY}Length: {len(hash_string)} characters{Colors.ENDC}\n")
    
    # Group by confidence
    high_confidence = [r for r in results if r["confidence"] >= 70]
    medium_confidence = [r for r in results if 50 <= r["confidence"] < 70]
    low_confidence = [r for r in results if r["confidence"] < 50]
    
    if high_confidence:
        print(f"{Colors.GREEN}{Colors.BOLD}[+] Most Likely Matches:{Colors.ENDC}")
        for result in high_confidence[:3]:
            bar = get_confidence_bar(result['confidence'])
            print(f"    {Colors.GREEN}[+]{Colors.ENDC} {Colors.BOLD}{result['type']:<30}{Colors.ENDC} {Colors.GRAY}({result['category']}){Colors.ENDC}")
            print(f"        {bar} {Colors.WHITE}{result['confidence']}%{Colors.ENDC}")
    
    if medium_confidence and verbose:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}[~] Possible Matches:{Colors.ENDC}")
        for result in medium_confidence[:5]:
            bar = get_confidence_bar(result['confidence'])
            print(f"    {Colors.YELLOW}[~]{Colors.ENDC} {result['type']:<30} {Colors.GRAY}({result['category']}){Colors.ENDC}")
            print(f"        {bar} {Colors.WHITE}{result['confidence']}%{Colors.ENDC}")
    
    if low_confidence and verbose:
        print(f"\n{Colors.RED}{Colors.BOLD}[-] Less Likely Matches:{Colors.ENDC}")
        for result in low_confidence[:5]:
            bar = get_confidence_bar(result['confidence'])
            print(f"    {Colors.RED}[-]{Colors.ENDC} {Colors.GRAY}{result['type']:<30} ({result['category']}){Colors.ENDC}")
            print(f"        {bar} {Colors.WHITE}{result['confidence']}%{Colors.ENDC}")
    
    if not verbose and (medium_confidence or low_confidence):
        print(f"\n{Colors.BLUE}[i] Use --verbose flag to see {len(medium_confidence) + len(low_confidence)} more possible matches{Colors.ENDC}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Enhanced Hash Identifier - Identify hash types and cryptographic algorithms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hash_id.py 5d41402abc4b2a76b9719d911017c592
  python hash_id.py -f hashes.txt
  python hash_id.py -v 098f6bcd4621d373cade4e832627b4f6
  
Categories:
  - MD Family: MD2, MD4, MD5, NTLM
  - SHA Family: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
  - CMS: Joomla, Wordpress, phpBB
  - Database: MySQL
  - Framework: Django
  - Unix/Linux: DES(Unix), SHA-256(Unix)
        """
    )
    
    parser.add_argument("hash", nargs="?", help="Hash string to identify")
    parser.add_argument("-f", "--file", help="File containing hashes (one per line)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all possible matches")
    parser.add_argument("--version", action="version", version=f"Hash Identifier v{VERSION}")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner display")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    # Disable colors if requested or if not in a terminal
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    
    # Display banner
    if not args.no_banner:
        print(get_banner())
    
    identifier = HashIdentifier()
    
    # Handle file input
    if args.file:
        try:
            with open(args.file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
            
            print(f"{Colors.CYAN}[*] Processing {len(hashes)} hashes from {args.file}{Colors.ENDC}\n")
            for i, hash_string in enumerate(hashes, 1):
                print(f"{Colors.MAGENTA}[{i}/{len(hashes)}]{Colors.ENDC}")
                results = identifier.identify(hash_string)
                display_results(results, hash_string, args.verbose)
                if i < len(hashes):
                    print(f"\n{Colors.GRAY}{'=' * 70}{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.RED}[!] Error: File '{args.file}' not found{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file: {e}{Colors.ENDC}")
            sys.exit(1)
    
    # Handle single hash input
    elif args.hash:
        results = identifier.identify(args.hash)
        display_results(results, args.hash, args.verbose)
    
    # Interactive mode
    else:
        print(f"{Colors.CYAN}[*] Interactive Mode - Enter hashes to identify (Ctrl+C to exit){Colors.ENDC}\n")
        try:
            while True:
                hash_input = input(f"{Colors.BOLD}{Colors.YELLOW}HASH{Colors.ENDC}{Colors.YELLOW}>{Colors.ENDC} ").strip()
                if not hash_input:
                    continue
                
                results = identifier.identify(hash_input)
                display_results(results, hash_input, args.verbose)
                print(f"\n{Colors.GRAY}{'-' * 70}{Colors.ENDC}\n")
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.CYAN}[*] Goodbye!{Colors.ENDC}")
            sys.exit(0)


if __name__ == "__main__":
    main()
