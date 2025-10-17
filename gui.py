#!/usr/bin/env python3
import urllib.parse
import re
import time
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.keys import Keys
from config import config

class XSSScanner:
    def __init__(self, verbose=False):
        self.results = []
        self.driver_pool = []
        self.lock = threading.Lock()
        self.verbose = verbose
        self.scan_start_time = None
        self.driver = None

    def log(self, message, level="info"):
        """Enhanced logging with levels"""
        if level == "debug" and not self.verbose:
            return
            
        prefixes = {
            "info": "[*]",
            "warn": "[!]",
            "debug": "[DEBUG]",
            "success": "[+]",
            "error": "[-]"
        }
        prefix = prefixes.get(level, "[*]")
        print(f"{prefix} {message}")

    def setup_driver(self):
        """Setup browser instance with enhanced options"""
        self.log("Setting up browser instance...")
        
        try:
            options = Options()
            
            # Enhanced Chrome options for better compatibility
            if config.headless:
                options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-web-security")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument(f"--user-agent={config.user_agent}")
            options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
            options.add_experimental_option('useAutomationExtension', False)
            
            # Additional security bypass options
            options.add_argument("--disable-xss-auditor")
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            self.driver.set_script_timeout(config.timeout)
            self.driver.set_page_load_timeout(config.timeout)
            self.log("Browser instance initialized successfully", "debug")
            
        except WebDriverException as e:
            self.log(f"WebDriver initialization failed: {e}", "error")
            # Try with simpler options
            try:
                options = Options()
                if config.headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                self.driver = webdriver.Chrome(options=options)
                self.log("Browser instance initialized with fallback options", "debug")
            except Exception as e2:
                self.log(f"Fallback WebDriver also failed: {e2}", "error")
                raise

    def close_driver(self):
        """Cleanup browser instance"""
        self.log("Closing browser instance...", "debug")
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                self.log(f"Error closing driver: {e}", "debug")
            self.driver = None

    def scan_url(self, target_url, payload_category="all", test_forms=True, test_headers=True):
        """Main scanning function with enhanced capabilities"""
        self.scan_start_time = time.time()
        self.log(f"Starting XSS scan for: {target_url}")
        self.log(f"Payload category: {payload_category}")
        
        payloads = config.get_payloads(payload_category)
        if not payloads:
            self.log("No payloads loaded!", "error")
            return []

        self.log(f"Loaded {len(payloads)} payloads")
        
        try:
            self.setup_driver()
            
            # Test different injection points
            self.log("Beginning comprehensive XSS testing...")
            
            url_results = self.test_url_parameters(target_url, payloads)
            self.results.extend(url_results)
            self.log(f"URL parameter testing: {len(url_results)} vulnerabilities found")
            
            fragment_results = self.test_url_fragments(target_url, payloads)
            self.results.extend(fragment_results)
            self.log(f"URL fragment testing: {len(fragment_results)} vulnerabilities found")
            
            if test_forms:
                form_results = self.test_forms(target_url, payloads)
                self.results.extend(form_results)
                self.log(f"Form testing: {len(form_results)} vulnerabilities found")
                
            if test_headers:
                header_results = self.test_headers(target_url, payloads)
                self.results.extend(header_results)
                self.log(f"Header testing: {len(header_results)} vulnerabilities found")

        except Exception as e:
            self.log(f"Scan error: {e}", "error")
        finally:
            self.close_driver()

        scan_time = time.time() - self.scan_start_time
        self.log(f"Scan completed in {scan_time:.2f} seconds. Total vulnerabilities: {len(self.results)}")
        return self.results

    def test_url_parameters(self, base_url, payloads):
        """Enhanced URL parameter testing with multiple detection methods"""
        self.log("Testing URL parameters with enhanced detection...")
        vulnerabilities = []
        
        parsed = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Test parameters to try
        test_parameters = ['q', 'search', 'id', 'name', 'query', 'keyword', 'term', 
                          'input', 'data', 'value', 'user', 'username', 'email']
        
        parameters_to_test = list(query_params.keys()) if query_params else test_parameters
        
        for param in parameters_to_test:
            self.log(f"Testing parameter: {param}", "debug")
            
            for payload_idx, payload in enumerate(payloads):
                try:
                    # Create test URL
                    if query_params:
                        new_params = query_params.copy()
                        new_params[param] = [payload]
                        new_query = urllib.parse.urlencode(new_params, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    else:
                        test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    
                    if self.verbose:
                        self.log(f"Testing: {test_url[:120]}...", "debug")
                    
                    # Test with multiple detection methods
                    detection_result = self.detect_xss_advanced(test_url, payload, param)
                    
                    if detection_result['vulnerable']:
                        vuln_info = {
                            'type': 'URL Parameter',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'detection_method': detection_result['method'],
                            'evidence': detection_result.get('evidence', '')
                        }
                        vulnerabilities.append(vuln_info)
                        self.log(f"XSS found in parameter '{param}' using {detection_result['method']}", "success")
                        
                        # If we found one vulnerability with alert, no need to test more payloads for this param
                        if detection_result['method'] == 'alert_execution':
                            break
                            
                except Exception as e:
                    self.log(f"Error testing parameter {param}: {e}", "debug")
        
        return vulnerabilities

    def test_url_fragments(self, base_url, payloads):
        """Enhanced URL fragment testing for DOM-based XSS"""
        self.log("Testing URL fragments for DOM XSS...")
        vulnerabilities = []
        
        for payload_idx, payload in enumerate(payloads):
            try:
                test_url = f"{base_url}#{urllib.parse.quote(payload)}"
                
                if self.verbose:
                    self.log(f"Testing fragment: {test_url[:100]}...", "debug")
                
                detection_result = self.detect_xss_advanced(test_url, payload, 'fragment')
                
                if detection_result['vulnerable']:
                    vulnerabilities.append({
                        'type': 'URL Fragment',
                        'payload': payload,
                        'url': test_url,
                        'detection_method': detection_result['method'],
                        'evidence': detection_result.get('evidence', '')
                    })
                    self.log(f"DOM XSS found in fragment using {detection_result['method']}", "success")
                    
            except Exception as e:
                self.log(f"Error testing fragment: {e}", "debug")
                
        return vulnerabilities

    def test_forms(self, url, payloads):
        """Enhanced form testing with better detection"""
        self.log("Testing forms for XSS vulnerabilities...")
        vulnerabilities = []
        
        if not self.driver:
            return vulnerabilities
            
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, config.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Find all forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            self.log(f"Found {len(forms)} forms to test")
            
            if not forms:
                return vulnerabilities
                
            for form_idx, form in enumerate(forms):
                self.log(f"Testing form {form_idx + 1}/{len(forms)}", "debug")
                
                # Get all input elements
                inputs = form.find_elements(By.XPATH, ".//input[@type='text'] | .//input[@type='search'] | .//input[not(@type)] | .//textarea")
                
                if not inputs:
                    self.log(f"No suitable inputs found in form {form_idx + 1}", "debug")
                    continue
                    
                self.log(f"Found {len(inputs)} input fields in form {form_idx + 1}", "debug")
                
                for input_idx, inp in enumerate(inputs):
                    input_name = inp.get_attribute("name") or inp.get_attribute("id") or f"input_{input_idx}"
                    self.log(f"Testing input: {input_name}", "debug")
                    
                    # Test with a subset of payloads for forms (to avoid timeouts)
                    for payload_idx, payload in enumerate(payloads[:8]):
                        try:
                            # Store original page for navigation
                            original_url = self.driver.current_url
                            
                            # Clear and set payload
                            inp.clear()
                            inp.send_keys(payload)
                            
                            # Try different submission methods
                            submitted = False
                            
                            # Method 1: Direct form submit
                            try:
                                form.submit()
                                submitted = True
                            except:
                                pass
                            
                            # Method 2: Click submit button
                            if not submitted:
                                submit_buttons = form.find_elements(By.XPATH, 
                                    ".//input[@type='submit'] | .//button[@type='submit'] | .//input[@type='image']")
                                if submit_buttons:
                                    submit_buttons[0].click()
                                    submitted = True
                            
                            # Method 3: Press Enter
                            if not submitted:
                                inp.send_keys(Keys.RETURN)
                                submitted = True
                            
                            if submitted:
                                # Wait for page load
                                time.sleep(2)
                                
                                # Check for XSS with multiple methods
                                current_url = self.driver.current_url
                                detection_result = self.detect_xss_advanced(current_url, payload, f"form_{input_name}")
                                
                                if detection_result['vulnerable']:
                                    vulnerabilities.append({
                                        'type': 'Form Input',
                                        'form_index': form_idx,
                                        'input_name': input_name,
                                        'payload': payload,
                                        'url': current_url,
                                        'detection_method': detection_result['method'],
                                        'evidence': detection_result.get('evidence', '')
                                    })
                                    self.log(f"XSS found in form input '{input_name}'", "success")
                                    break  # Stop testing this input after first success
                            
                            # Navigate back to original page
                            if self.driver.current_url != original_url:
                                self.driver.get(original_url)
                                WebDriverWait(self.driver, config.timeout).until(
                                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                                )
                                
                            # Re-find the form and input
                            forms = self.driver.find_elements(By.TAG_NAME, "form")
                            if form_idx < len(forms):
                                form = forms[form_idx]
                                inputs = form.find_elements(By.XPATH, ".//input[@type='text'] | .//input[@type='search'] | .//input[not(@type)] | .//textarea")
                                if input_idx < len(inputs):
                                    inp = inputs[input_idx]
                            else:
                                break
                                
                        except Exception as e:
                            self.log(f"Error testing form input: {e}", "debug")
                            # Try to recover by going back to original URL
                            try:
                                self.driver.get(url)
                                WebDriverWait(self.driver, config.timeout).until(
                                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                                )
                                forms = self.driver.find_elements(By.TAG_NAME, "form")
                            except:
                                break
                            
        except Exception as e:
            self.log(f"Form testing error: {e}", "error")
            
        return vulnerabilities

    def test_headers(self, url, payloads):
        """Test XSS through HTTP headers"""
        self.log("Testing HTTP headers...")
        # TODO: Implement header-based XSS testing
        return []

    def detect_xss_advanced(self, url, payload, context):
        """Enhanced XSS detection with multiple methods"""
        if not self.driver:
            return {'vulnerable': False, 'method': 'no_driver'}
            
        detection_result = {
            'vulnerable': False,
            'method': 'none',
            'evidence': ''
        }
        
        try:
            # Navigate to the URL
            self.driver.get(url)
            
            # Method 1: Alert-based detection (most reliable)
            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                if any(detection in alert_text for detection in config.detection_strings):
                    detection_result.update({
                        'vulnerable': True,
                        'method': 'alert_execution',
                        'evidence': f"Alert triggered with text: {alert_text}"
                    })
                    return detection_result
            except TimeoutException:
                pass  # No alert detected
            
            # Method 2: Reflection analysis with context detection
            page_source = self.driver.page_source
            reflected_locations = self.analyze_reflection(page_source, payload)
            
            if reflected_locations:
                # Check if reflection is in dangerous context
                dangerous_contexts = self.check_dangerous_contexts(payload)
                
                if dangerous_contexts:
                    detection_result.update({
                        'vulnerable': True,
                        'method': 'dangerous_reflection',
                        'evidence': f"Payload reflected in dangerous context: {dangerous_contexts}"
                    })
                    return detection_result
                
                # If we have reflection but no dangerous context, still report it
                detection_result.update({
                    'vulnerable': False,  # Not exploitable but interesting
                    'method': 'reflection_only',
                    'evidence': f"Payload reflected but not in exploitable context: {reflected_locations}"
                })
            
            # Method 3: DOM-based XSS detection
            dom_vulnerabilities = self.check_dom_xss(payload)
            if dom_vulnerabilities:
                detection_result.update({
                    'vulnerable': True,
                    'method': 'dom_based',
                    'evidence': f"DOM-based XSS detected: {dom_vulnerabilities}"
                })
                return detection_result
                
            # Method 4: Check for JavaScript execution in attributes
            attribute_xss = self.check_attribute_xss(payload)
            if attribute_xss:
                detection_result.update({
                    'vulnerable': True,
                    'method': 'attribute_execution',
                    'evidence': f"XSS in HTML attributes: {attribute_xss}"
                })
                return detection_result
                
        except Exception as e:
            self.log(f"Detection error for {context}: {e}", "debug")
            
        return detection_result

    def analyze_reflection(self, page_source, payload):
        """Analyze how and where the payload is reflected"""
        reflections = []
        
        # Look for exact reflection
        if payload in page_source:
            reflections.append("exact_reflection")
        
        # Look for URL-encoded reflection
        encoded_payload = urllib.parse.quote(payload)
        if encoded_payload in page_source:
            reflections.append("url_encoded_reflection")
        
        # Look for partial reflection
        if len(payload) > 5:
            for i in range(3, len(payload) - 2):
                partial = payload[i:i+3]
                if partial in page_source:
                    reflections.append("partial_reflection")
                    break
        
        return reflections if reflections else None

    def check_dangerous_contexts(self, payload):
        """Check if payload appears in dangerous HTML/JavaScript contexts"""
        dangerous_contexts = []
        
        try:
            # Check inside script tags
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                script_content = script.get_attribute("innerHTML")
                if payload in script_content:
                    dangerous_contexts.append("inside_script_tag")
                    break
            
            # Check in event handlers
            event_attributes = ['onclick', 'onload', 'onerror', 'onmouseover', 'onmouseenter', 
                              'onfocus', 'onblur', 'onchange', 'onsubmit']
            
            for attr in event_attributes:
                elements = self.driver.find_elements(By.XPATH, f"//*[@{attr}]")
                for element in elements:
                    attr_value = element.get_attribute(attr)
                    if attr_value and payload in attr_value:
                        dangerous_contexts.append(f"event_handler_{attr}")
                        break
            
            # Check in href attributes with javascript:
            links = self.driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                href = link.get_attribute("href")
                if href and "javascript:" in href and payload in href:
                    dangerous_contexts.append("javascript_href")
                    break
                    
        except Exception as e:
            self.log(f"Error checking dangerous contexts: {e}", "debug")
            
        return dangerous_contexts if dangerous_contexts else None

    def check_dom_xss(self, payload):
        """Check for DOM-based XSS vulnerabilities"""
        dom_indicators = []
        
        try:
            # Check document.write and similar
            scripts = self.driver.find_elements(By.TAG_NAME, "script")
            dom_functions = ['document.write', 'document.writeln', 'innerHTML', 'outerHTML', 
                           'eval(', 'setTimeout', 'setInterval', 'Function(']
            
            for script in scripts:
                script_content = script.get_attribute("innerHTML")
                if script_content:
                    for func in dom_functions:
                        if func in script_content and payload in script_content:
                            dom_indicators.append(f"dom_function_{func}")
                            break
            
            # Check location.hash and URL-based DOM XSS
            if 'location.hash' in self.driver.page_source or 'location.search' in self.driver.page_source:
                dom_indicators.append("location_based_dom")
                
        except Exception as e:
            self.log(f"Error checking DOM XSS: {e}", "debug")
            
        return dom_indicators if dom_indicators else None

    def check_attribute_xss(self, payload):
        """Check for XSS in HTML attributes"""
        attribute_vulns = []
        
        try:
            # Check for unquoted attributes that contain our payload
            elements = self.driver.find_elements(By.XPATH, "//*[@*]")
            
            for element in elements:
                attributes = self.driver.execute_script(
                    "var items = {}; "
                    "for (var index = 0; index < arguments[0].attributes.length; ++index) { "
                    "  items[arguments[0].attributes[index].name] = arguments[0].attributes[index].value "
                    "} "
                    "return items;", element)
                
                for attr_name, attr_value in attributes.items():
                    if payload in attr_value:
                        # Check if it's a dangerous context
                        if attr_name.startswith('on') or attr_name in ['href', 'src', 'action']:
                            attribute_vulns.append(f"attribute_{attr_name}")
                            break
                            
        except Exception as e:
            self.log(f"Error checking attribute XSS: {e}", "debug")


            
#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import threading
import time
import sys
import os
from datetime import datetime
from pathlib import Path

# Add current directory to path to ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from scanner import XSSScanner
    from reporter import ReportGenerator
    from config import config
    SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"Import warning: {e}")
    SCANNER_AVAILABLE = False
except Exception as e:
    print(f"Initialization warning: {e}")
    SCANNER_AVAILABLE = False

class XSSScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XSScan v3.0 - Advanced XSS Scanner")
        self.root.geometry("1200x800")
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        self.scan_results = []
        self.scan_start_time = 0
        
        # Check if scanner is available
        if not SCANNER_AVAILABLE:
            self.show_scanner_error()
        else:
            self.setup_ui()
        
    def show_scanner_error(self):
        """Show error message if scanner dependencies are missing"""
        error_frame = ttk.Frame(self.root, padding="20")
        error_frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(error_frame, text="❌ Scanner Initialization Error", 
                 font=("Arial", 16, "bold"), foreground="red").pack(pady=10)
        
        error_text = scrolledtext.ScrolledText(error_frame, wrap=tk.WORD, width=80, height=15)
        error_text.pack(expand=True, fill=tk.BOTH, pady=10)
        
        error_msg = """
🚨 XSS Scanner Dependencies Missing

The scanner requires the following to work:

1. REQUIRED: Selenium
   Run: pip install selenium

2. REQUIRED: Chrome Browser
   - Make sure Google Chrome is installed
   - Download from: https://www.google.com/chrome/

3. REQUIRED: ChromeDriver
   - Download from: https://chromedriver.chromium.org/
   - Make sure it matches your Chrome version
   - Place chromedriver.exe in your PATH or in this folder

📋 Quick Setup Commands:
───────────────────────
pip install selenium

Then download ChromeDriver and place it in:
- Windows: C:\\Windows\\System32\\
- Or any folder in your PATH environment variable

🔧 Alternative Setup:
─────────────────────
You can use the CLI version which might have fewer dependencies:
python xsscan.py "http://testphp.vulnweb.com/search.php?test=query"

After installing the dependencies, please restart the GUI.
"""
        error_text.insert(tk.END, error_msg)
        error_text.config(state=tk.DISABLED)
        
        button_frame = ttk.Frame(error_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="🔄 Retry", command=self.retry_initialization).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ Exit", command=self.root.quit).pack(side=tk.LEFT, padx=5)
        
    def retry_initialization(self):
        """Retry initializing the scanner"""
        try:
            from scanner import XSSScanner
            from reporter import ReportGenerator
            from config import config
            global SCANNER_AVAILABLE
            SCANNER_AVAILABLE = True
            
            # Clear the window and setup UI
            for widget in self.root.winfo_children():
                widget.destroy()
            self.setup_ui()
            
        except Exception as e:
            messagebox.showerror("Initialization Failed", 
                               f"Still unable to initialize scanner:\n{str(e)}")
        
    def setup_ui(self):
        """Setup the main GUI interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        # Title
        title_label = ttk.Label(main_frame, text="🚀 XSScan v3.0 - Advanced XSS Scanner", 
                               font=("Arial", 18, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="🔧 Scan Configuration", padding="15")
        input_frame.pack(fill=tk.X, pady=(0, 15))
        
        # URL input
        url_frame = ttk.Frame(input_frame)
        url_frame.pack(fill=tk.X, pady=8)
        
        ttk.Label(url_frame, text="🎯 Target URL:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_frame, width=70, font=("Arial", 10))
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        self.url_entry.insert(0, "http://testphp.vulnweb.com/search.php?test=query")
        
        # Configuration grid
        config_frame = ttk.Frame(input_frame)
        config_frame.pack(fill=tk.X, pady=10)
        
        # Left side config
        left_config = ttk.Frame(config_frame)
        left_config.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(left_config, text="Payload Category:").pack(anchor=tk.W)
        self.category_var = tk.StringVar(value="basic")
        category_combo = ttk.Combobox(left_config, textvariable=self.category_var, 
                                    values=["basic", "advanced", "polyglot", "all"], 
                                    state="readonly", width=15)
        category_combo.pack(anchor=tk.W, pady=5)
        
        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(left_config, text="Verbose Output", variable=self.verbose_var).pack(anchor=tk.W, pady=2)
        
        # Right side config
        right_config = ttk.Frame(config_frame)
        right_config.pack(side=tk.RIGHT, fill=tk.X)
        
        options_frame = ttk.Frame(right_config)
        options_frame.pack(anchor=tk.E)
        
        self.forms_var = tk.BooleanVar(value=True)
        self.headers_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Test Forms", variable=self.forms_var).pack(anchor=tk.E, pady=2)
        ttk.Checkbutton(options_frame, text="Test Headers", variable=self.headers_var).pack(anchor=tk.E, pady=2)
        
        timeout_frame = ttk.Frame(options_frame)
        timeout_frame.pack(anchor=tk.E, pady=2)
        ttk.Label(timeout_frame, text="Timeout (s):").pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="15")
        timeout_spin = ttk.Spinbox(timeout_frame, from_=5, to=60, textvariable=self.timeout_var, width=5)
        timeout_spin.pack(side=tk.LEFT, padx=5)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=15)
        
        self.scan_btn = ttk.Button(button_frame, text="🚀 Start Scan", 
                                 command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ Stop Scan", 
                                 command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.load_btn = ttk.Button(button_frame, text="📁 Load Report", 
                                 command=self.load_report)
        self.load_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="🗑️ Clear Results", 
                                  command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(button_frame, text="💾 Export Report", 
                                   command=self.export_report)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_frame, text="📊 Scan Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Progress bar
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Progress labels
        progress_labels_frame = ttk.Frame(progress_frame)
        progress_labels_frame.pack(fill=tk.X)
        
        self.progress_label = ttk.Label(progress_labels_frame, text="Ready to start scan")
        self.progress_label.pack(side=tk.LEFT)
        
        self.stats_label = ttk.Label(progress_labels_frame, text="Vulnerabilities found: 0 | Time elapsed: 0s")
        self.stats_label.pack(side=tk.RIGHT)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="📋 Scan Results", padding="10")
        results_frame.pack(expand=True, fill=tk.BOTH, pady=(0, 10))
        
        # Create notebook for different views
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(expand=True, fill=tk.BOTH)
        
        # Console output tab
        console_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(console_frame, text="Console Output")
        
        self.console_text = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, 
                                                     font=("Consolas", 9))
        self.console_text.pack(expand=True, fill=tk.BOTH)
        self.console_text.config(state=tk.DISABLED)
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(vuln_frame, text="Vulnerabilities")
        
        # Treeview for vulnerabilities
        tree_frame = ttk.Frame(vuln_frame)
        tree_frame.pack(expand=True, fill=tk.BOTH)
        
        columns = ('Type', 'Parameter', 'Payload', 'Method', 'URL')
        self.vuln_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        # Define headings
        for col in columns:
            self.vuln_tree.heading(col, text=col)
        
        # Set column widths
        self.vuln_tree.column('Type', width=120)
        self.vuln_tree.column('Parameter', width=100)
        self.vuln_tree.column('Payload', width=150)
        self.vuln_tree.column('Method', width=150)
        self.vuln_tree.column('URL', width=300)
        
        # Scrollbar for treeview
        vuln_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        vuln_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Summary tab
        summary_frame = ttk.Frame(self.results_notebook, padding="5")
        self.results_notebook.add(summary_frame, text="Scan Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, 
                                                     font=("Arial", 10))
        self.summary_text.pack(expand=True, fill=tk.BOTH)
        self.summary_text.config(state=tk.DISABLED)
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="🟢 Ready to scan")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, 
                              padding="5", background="#f0f0f0")
        status_bar.pack(fill=tk.X)
        
        # Add welcome message
        self.log_to_console("🚀 XSScan v3.0 GUI Initialized Successfully", "success")
        self.log_to_console("📍 Ready to scan for XSS vulnerabilities", "info")
        self.log_to_console("💡 Tip: Use the test URL provided or enter your own target", "info")
        
    def log_to_console(self, message, level="info"):
        """Add message to console"""
        self.console_text.config(state=tk.NORMAL)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        if level == "success":
            prefix = "[+]"
        elif level == "warning":
            prefix = "[!]"
        elif level == "error":
            prefix = "[-]"
        elif level == "debug":
            prefix = "[DEBUG]"
        else:
            prefix = "[*]"
        
        formatted_message = f"{timestamp} {prefix} {message}\n"
        self.console_text.insert(tk.END, formatted_message)
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)
        
    def start_scan(self):
        """Start the XSS scan in a separate thread"""
        if not SCANNER_AVAILABLE:
            messagebox.showerror("Scanner Not Available", 
                               "Scanner dependencies are not available. Please check the requirements.")
            return
            
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
        
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.is_scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.status_var.set("🟡 Scanning in progress...")
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(target=self.run_scan, args=(url,), daemon=True)
        self.scan_thread.start()
        
        # Start progress updates
        self.update_progress()
        
    def run_scan(self, url):
        """Run the actual scan (in separate thread)"""
        try:
            self.log_to_console(f"Starting XSS scan for: {url}", "info")
            self.log_to_console(f"Payload category: {self.category_var.get()}", "info")
            
            # Update config
            from config import config
            config.timeout = int(self.timeout_var.get())
            
            # Initialize scanner
            self.scanner = XSSScanner(verbose=self.verbose_var.get())
            self.scan_start_time = time.time()
            
            # Perform the scan
            self.scan_results = self.scanner.scan_url(
                target_url=url,
                payload_category=self.category_var.get(),
                test_forms=self.forms_var.get(),
                test_headers=self.headers_var.get()
            )
            
            # Update UI in main thread
            self.root.after(0, self.scan_completed)
            
        except Exception as e:
            self.root.after(0, lambda: self.scan_failed(str(e)))
            
    def update_progress(self):
        """Update progress indicators during scan"""
        if self.is_scanning:
            elapsed_time = int(time.time() - self.scan_start_time)
            vuln_count = len(self.scan_results)
            self.stats_label.config(text=f"Vulnerabilities found: {vuln_count} | Time elapsed: {elapsed_time}s")
            self.root.after(1000, self.update_progress)
            
    def scan_completed(self):
        """Handle scan completion"""
        self.is_scanning = False
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        scan_time = time.time() - self.scan_start_time
        vuln_count = len(self.scan_results)
        
        self.status_var.set(f"🟢 Scan completed in {scan_time:.2f}s - Found {vuln_count} vulnerabilities")
        self.log_to_console(f"Scan completed in {scan_time:.2f} seconds", "success")
        self.log_to_console(f"Total vulnerabilities found: {vuln_count}", "success")
        
        # Update results display
        self.update_results_display()
        
        # Show completion message
        if vuln_count > 0:
            messagebox.showinfo("Scan Complete", 
                              f"Scan completed!\nFound {vuln_count} XSS vulnerabilities.")
        else:
            messagebox.showinfo("Scan Complete", "Scan completed! No vulnerabilities found.")
            
    def scan_failed(self, error_message):
        """Handle scan failure"""
        self.is_scanning = False
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        self.status_var.set("🔴 Scan failed")
        self.log_to_console(f"Scan failed: {error_message}", "error")
        messagebox.showerror("Scan Failed", f"The scan failed with error:\n{error_message}")
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.is_scanning and self.scanner:
            self.is_scanning = False
            self.scan_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.progress.stop()
            self.status_var.set("🟠 Scan stopped by user")
            self.log_to_console("Scan stopped by user", "warning")
            
    def update_results_display(self):
        """Update all results displays"""
        # Update vulnerabilities treeview
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        for vuln in self.scan_results:
            self.vuln_tree.insert('', tk.END, values=(
                vuln.get('type', ''),
                vuln.get('parameter', ''),
                vuln.get('payload', '')[:50] + '...' if len(vuln.get('payload', '')) > 50 else vuln.get('payload', ''),
                vuln.get('detection_method', ''),
                vuln.get('url', '')[:80] + '...' if len(vuln.get('url', '')) > 80 else vuln.get('url', '')
            ))
        
        # Update summary
        self.update_summary()
        
    def update_summary(self):
        """Update the summary tab"""
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        
        scan_time = time.time() - self.scan_start_time
        vuln_count = len(self.scan_results)
        
        summary = f"""
XSScan Scan Summary
===================

Scan Information:
-----------------
• Target URL: {self.url_entry.get()}
• Scan Duration: {scan_time:.2f} seconds
• Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
• Payload Category: {self.category_var.get()}
• Forms Tested: {self.forms_var.get()}
• Headers Tested: {self.headers_var.get()}

Vulnerability Summary:
----------------------
• Total Vulnerabilities: {vuln_count}

"""
        
        if vuln_count > 0:
            # Group by type
            by_type = {}
            for vuln in self.scan_results:
                vuln_type = vuln.get('type', 'Unknown')
                by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
            
            summary += "Breakdown by Type:\n"
            summary += "------------------\n"
            for vuln_type, count in by_type.items():
                summary += f"• {vuln_type}: {count}\n"
            
            summary += "\nDetection Methods:\n"
            summary += "------------------\n"
            methods = {}
            for vuln in self.scan_results:
                method = vuln.get('detection_method', 'Unknown')
                methods[method] = methods.get(method, 0) + 1
            
            for method, count in methods.items():
                summary += f"• {method}: {count}\n"
                
            summary += f"\nRisk Level: {'HIGH' if vuln_count > 0 else 'LOW'}\n"
        else:
            summary += "No vulnerabilities detected. The target appears to be secure against the tested XSS payloads.\n"
        
        self.summary_text.insert(tk.END, summary)
        self.summary_text.config(state=tk.DISABLED)
        
    def load_report(self):
        """Load a saved scan report"""
        file_path = filedialog.askopenfilename(
            title="Select Scan Report",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    report_data = json.load(f)
                
                # Update UI with loaded data
                self.scan_results = report_data.get('vulnerabilities', [])
                self.update_results_display()
                
                # Switch to summary tab
                self.results_notebook.select(2)
                
                self.status_var.set("🟢 Report loaded successfully")
                messagebox.showinfo("Success", "Scan report loaded successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load report: {e}")
                
    def export_report(self):
        """Export current results to a file"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export!")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Scan Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                from reporter import ReportGenerator
                scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
                reporter = ReportGenerator()
                reporter.save_report(self.scan_results, file_path, scan_time, self.url_entry.get())
                self.status_var.set("🟢 Report exported successfully")
                messagebox.showinfo("Success", f"Report exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")
                
    def clear_results(self):
        """Clear all results and console"""
        self.scan_results = []
        self.console_text.config(state=tk.NORMAL)
        self.console_text.delete(1.0, tk.END)
        self.console_text.config(state=tk.DISABLED)
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.config(state=tk.DISABLED)
        self.stats_label.config(text="Vulnerabilities found: 0 | Time elapsed: 0s")
        self.status_var.set("🟢 Ready to scan")

def main():
    try:
        root = tk.Tk()
        app = XSSScannerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()