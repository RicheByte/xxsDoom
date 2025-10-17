#!/usr/bin/env python3
import argparse
import sys
import time
from pathlib import Path
from scanner import XSSScanner
from reporter import ReportGenerator
from config import config

def banner():
    print("""
    ╔═╗╔═╗╔═╗  ╔═╗╔═╗╔═╗╔═╗╔╗╔╔═╗╔═╗
    ╚═╗╠═╝║ ║  ║  ║ ║║ ║║ ║║║║╠═╣╚═╗
    ╚═╝╩  ╚═╝  ╚═╝╚═╝╚═╝╚═╝╝╚╝╩ ╩╚═╝
            XSS Scanner v2.0 - Enhanced
    """)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Enhanced XSS Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-c', '--category', choices=['basic', 'advanced', 'polyglot', 'all'], 
                       default='basic', help='Payload category (default: basic)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--no-forms', action='store_true', help='Skip form testing')
    parser.add_argument('--no-headers', action='store_true', help='Skip header testing')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    return parser.parse_args()

def main():
    banner()
    args = parse_arguments()
    
    # Update config
    config.timeout = args.timeout
    config.delay = args.delay
    
    # Initialize scanner with verbose mode
    scanner = XSSScanner(verbose=args.verbose)
    
    try:
        # Start scan
        start_time = time.time()
        results = scanner.scan_url(
            target_url=args.url,
            payload_category=args.category,
            test_forms=not args.no_forms,
            test_headers=not args.no_headers
        )
        scan_time = time.time() - start_time
        
        # Generate report
        reporter = ReportGenerator()
        report = reporter.generate_console_report(results, scan_time, args.url)
        print(report)
        
        # Save results if output specified
        if args.output:
            reporter.save_report(results, args.output, scan_time, args.url)
            print(f"\n[+] Report saved to: {args.output}")
            
        # Save to default location
        default_report = config.reports_dir / f"scan_{int(time.time())}.json"
        reporter.save_report(results, default_report, scan_time, args.url)
        print(f"[+] Default report saved to: {default_report}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()