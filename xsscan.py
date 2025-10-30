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
    XSS Scanner v2.5 - AGGRESSIVE MODE
    """.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore'))

def parse_arguments():
    parser = argparse.ArgumentParser(description='Enhanced XSS Scanner with Aggressive Parallel Mode')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-c', '--category', choices=['basic', 'advanced', 'polyglot', 'all'], 
                       default='basic', help='Payload category (default: basic)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--no-forms', action='store_true', help='Skip form testing')
    parser.add_argument('--no-headers', action='store_true', help='Skip header testing')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Aggressive mode options
    parser.add_argument('-a', '--aggressive', action='store_true', 
                       help='🔥 Enable aggressive parallel scanning (faster)')
    parser.add_argument('--ultra', action='store_true', 
                       help='🔥🔥 Ultra aggressive mode (maximum speed)')
    parser.add_argument('--insane', action='store_true', 
                       help='🔥🔥🔥 INSANE mode - All resources (experimental)')
    parser.add_argument('--threads', type=int, 
                       help='Custom number of parallel threads (max 20 recommended)')
    
    return parser.parse_args()

def main():
    banner()
    args = parse_arguments()
    
    # Update config
    config.timeout = args.timeout
    config.delay = args.delay
    
    # Determine aggressive mode settings
    aggressive = args.aggressive or args.ultra or args.insane
    
    if args.threads:
        max_threads = min(args.threads, 20)  # Cap at 20 for stability
        mode_name = f"Custom ({max_threads} threads)"
    elif args.insane:
        max_threads = config.insane_threads
        mode_name = "🔥🔥🔥 INSANE MODE"
    elif args.ultra:
        max_threads = config.ultra_aggressive_threads
        mode_name = "🔥🔥 ULTRA AGGRESSIVE"
    elif args.aggressive:
        max_threads = config.aggressive_threads
        mode_name = "🔥 AGGRESSIVE"
    else:
        max_threads = 1
        mode_name = "Standard"
    
    # Initialize scanner
    scanner = XSSScanner(
        verbose=args.verbose, 
        aggressive=aggressive,
        max_threads=max_threads
    )
    
    print(f"[*] Scan Mode: {mode_name}")
    if aggressive:
        print(f"[!] Aggressive mode enabled with {max_threads} worker threads")
        print(f"[!] This will spawn multiple browser instances for parallel testing")
        print(f"[!] Press Ctrl+C to abort if needed.\n")
    
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
        
        # Performance stats
        if aggressive and results:
            tests_per_second = len(results) / scan_time if scan_time > 0 else 0
            print(f"\n[*] Performance: {tests_per_second:.2f} vulnerabilities found per second")
        
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
        import traceback
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()