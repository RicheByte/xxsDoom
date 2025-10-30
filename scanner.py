#!/usr/bin/env python3
"""
Optimized XSS Scanner - Enhanced Performance and Reliability
AGGRESSIVE MODE: Parallel scanning with multi-threading
"""
import urllib.parse
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.keys import Keys

try:
    from webdriver_manager.chrome import ChromeDriverManager
    WEBDRIVER_MANAGER_AVAILABLE = True
except ImportError:
    WEBDRIVER_MANAGER_AVAILABLE = False

from config import config

class XSSScanner:
    def __init__(self, verbose=False, aggressive=False, max_threads=10):
        self.results = []
        self.driver = None
        self.verbose = verbose
        self.aggressive = aggressive
        # Limit max threads to reasonable amount to prevent resource exhaustion
        self.max_threads = min(max_threads, 20) if aggressive else 1
        self.scan_start_time = None
        self.tested_payloads = set()
        self.vulnerable_payloads = []
        self.results_lock = threading.Lock()
        self.driver_pool = []
        self.driver_lock = threading.Lock()
        self.max_pool_size = min(max_threads // 2, 10)  # Limit browser pool size
        
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
        timestamp = time.strftime("%H:%M:%S")
        print(f"{timestamp} {prefix} {message}")

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
            options.add_argument("--allow-running-insecure-content")
            options.add_argument("--ignore-certificate-errors")
            
            # Performance optimizations
            options.add_argument("--disable-extensions")
            options.add_argument("--disable-plugins")
            options.add_argument("--disable-images")  # Faster loading
            
            # Aggressive mode: reduce timeouts
            if self.aggressive:
                options.page_load_strategy = 'eager'
            
            # Try to use webdriver-manager for automatic ChromeDriver management
            if WEBDRIVER_MANAGER_AVAILABLE:
                try:
                    service = Service(ChromeDriverManager().install())
                    driver = webdriver.Chrome(service=service, options=options)
                    self.log("Browser initialized with webdriver-manager", "success")
                except Exception as e:
                    self.log(f"webdriver-manager failed, trying manual: {e}", "debug")
                    driver = webdriver.Chrome(options=options)
            else:
                driver = webdriver.Chrome(options=options)
                
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            timeout = config.timeout // 2 if self.aggressive else config.timeout
            driver.set_script_timeout(timeout)
            driver.set_page_load_timeout(timeout)
            
            if not self.aggressive:
                self.driver = driver
                self.log("Browser instance initialized successfully", "success")
            
            return driver
            
        except WebDriverException as e:
            self.log(f"WebDriver initialization failed: {e}", "error")
            # Try with simpler options
            try:
                options = Options()
                if config.headless:
                    options.add_argument("--headless")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                
                if WEBDRIVER_MANAGER_AVAILABLE:
                    service = Service(ChromeDriverManager().install())
                    driver = webdriver.Chrome(service=service, options=options)
                else:
                    driver = webdriver.Chrome(options=options)
                    
                self.log("Browser instance initialized with fallback options", "warn")
                if not self.aggressive:
                    self.driver = driver
                return driver
            except Exception as e2:
                self.log(f"Fallback WebDriver also failed: {e2}", "error")
                self.log("\nPlease install ChromeDriver:", "error")
                self.log("  Option 1: pip install webdriver-manager (recommended)", "error")
                self.log("  Option 2: Download from https://chromedriver.chromium.org/", "error")
                raise

    def close_driver(self, driver=None):
        """Cleanup browser instance"""
        target_driver = driver if driver else self.driver
        if target_driver:
            try:
                target_driver.quit()
                self.log("Browser instance closed", "debug")
            except Exception as e:
                self.log(f"Error closing driver: {e}", "debug")
        if not driver:
            self.driver = None
    
    def get_driver_from_pool(self):
        """Get a driver from pool or create new one in aggressive mode"""
        with self.driver_lock:
            if self.driver_pool:
                driver = self.driver_pool.pop()
                self.log(f"Reusing driver from pool (pool size: {len(self.driver_pool)})", "debug")
                return driver
            else:
                # Only create if under pool limit
                if not hasattr(self, '_active_drivers'):
                    self._active_drivers = 0
                if self._active_drivers >= self.max_pool_size:
                    # Wait a bit and retry from pool
                    pass
                else:
                    self._active_drivers += 1
                    self.log(f"Creating new driver ({self._active_drivers}/{self.max_pool_size})", "debug")
                    return self.setup_driver()
        
        # If we couldn't create, wait and try again from pool
        time.sleep(0.5)
        with self.driver_lock:
            if self.driver_pool:
                return self.driver_pool.pop()
        return None
    
    def return_driver_to_pool(self, driver):
        """Return driver to pool for reuse"""
        if not driver:
            return
        with self.driver_lock:
            if len(self.driver_pool) < self.max_pool_size:
                self.driver_pool.append(driver)
                self.log(f"Returned driver to pool (pool size: {len(self.driver_pool)})", "debug")
            else:
                self.close_driver(driver)
                if hasattr(self, '_active_drivers'):
                    self._active_drivers -= 1

    def scan_url(self, target_url, payload_category="basic", test_forms=True, test_headers=False):
        """Main scanning function with enhanced capabilities and aggressive parallel mode"""
        self.scan_start_time = time.time()
        self.log(f"Starting XSS scan for: {target_url}", "info")
        self.log(f"Payload category: {payload_category}", "info")
        
        if self.aggressive:
            self.log(f"🔥 AGGRESSIVE MODE ENABLED - {self.max_threads} parallel threads", "warn")
        
        payloads = config.get_payloads(payload_category)
        if not payloads:
            self.log("No payloads loaded!", "error")
            return []

        self.log(f"Loaded {len(payloads)} unique payloads", "info")
        
        try:
            if self.aggressive:
                # Aggressive parallel mode
                self._aggressive_scan(target_url, payloads, test_forms, test_headers)
            else:
                # Standard sequential mode
                self.setup_driver()
                self._standard_scan(target_url, payloads, test_forms, test_headers)

        except KeyboardInterrupt:
            self.log("Scan interrupted by user", "warn")
            raise
        except Exception as e:
            self.log(f"Scan error: {e}", "error")
        finally:
            # Cleanup all drivers
            if self.aggressive:
                with self.driver_lock:
                    for driver in self.driver_pool:
                        self.close_driver(driver)
                    self.driver_pool.clear()
            else:
                self.close_driver()

        scan_time = time.time() - self.scan_start_time
        self.log(f"Scan completed in {scan_time:.2f} seconds", "info")
        self.log(f"Total vulnerabilities found: {len(self.results)}", 
                "success" if self.results else "info")
        return self.results
    
    def _standard_scan(self, target_url, payloads, test_forms, test_headers):
        """Standard sequential scanning"""
        self.log("Beginning comprehensive XSS testing...", "info")
        
        # URL parameter testing
        url_results = self.test_url_parameters(target_url, payloads)
        self.results.extend(url_results)
        self.log(f"URL parameter testing: {len(url_results)} vulnerabilities found", 
                "success" if url_results else "info")
        
        # URL fragment testing
        fragment_results = self.test_url_fragments(target_url, payloads)
        self.results.extend(fragment_results)
        self.log(f"URL fragment testing: {len(fragment_results)} vulnerabilities found", 
                "success" if fragment_results else "info")
        
        # Form testing
        if test_forms:
            form_results = self.test_forms(target_url, payloads)
            self.results.extend(form_results)
            self.log(f"Form testing: {len(form_results)} vulnerabilities found", 
                    "success" if form_results else "info")
            
        # Header testing
        if test_headers:
            header_results = self.test_headers(target_url, payloads[:10])
            self.results.extend(header_results)
            self.log(f"Header testing: {len(header_results)} vulnerabilities found", 
                    "success" if header_results else "info")
    
    def _aggressive_scan(self, target_url, payloads, test_forms, test_headers):
        """Aggressive parallel scanning with thread pool"""
        self.log("🔥 Beginning AGGRESSIVE parallel XSS testing...", "warn")
        
        tasks = []
        
        # Create URL parameter tasks
        parsed = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        test_parameters = ['q', 'search', 'id', 'name', 'query', 'keyword', 'term', 
                          'input', 'data', 'value', 'user', 'username', 'email', 'page']
        parameters_to_test = list(query_params.keys()) if query_params else test_parameters[:5]
        
        for param in parameters_to_test:
            for payload in payloads:
                tasks.append(('url_param', target_url, param, payload))
        
        # Create fragment tasks - test all payloads
        for payload in payloads:
            tasks.append(('fragment', target_url, None, payload))
        
        self.log(f"Created {len(tasks)} parallel tasks", "info")
        
        # Execute tasks in parallel
        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._execute_task, task): task for task in tasks}
            
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    self.log(f"Progress: {completed}/{len(tasks)} tasks completed", "info")
                try:
                    result = future.result()
                    if result:
                        with self.results_lock:
                            self.results.append(result)
                            self.log(f"✓ Vulnerability found! Total: {len(self.results)}", "success")
                except Exception as e:
                    self.log(f"Task error: {e}", "debug")
        
        # Form testing (still sequential due to complexity)
        if test_forms:
            self.log("Testing forms (sequential)...", "info")
            driver = self.get_driver_from_pool()
            try:
                form_results = self._test_forms_with_driver(driver, target_url, payloads)
                self.results.extend(form_results)
                self.log(f"Form testing: {len(form_results)} vulnerabilities found", 
                        "success" if form_results else "info")
            finally:
                self.return_driver_to_pool(driver)
    
    def _execute_task(self, task):
        """Execute a single scan task with its own driver"""
        task_type, url, param, payload = task
        driver = self.get_driver_from_pool()
        
        if not driver:
            self.log("Could not get driver from pool, skipping task", "warn")
            return None
        
        try:
            if task_type == 'url_param':
                return self._test_single_url_param(driver, url, param, payload)
            elif task_type == 'fragment':
                return self._test_single_fragment(driver, url, payload)
        except Exception as e:
            self.log(f"Error in task {task_type}: {e}", "debug")
            return None
        finally:
            self.return_driver_to_pool(driver)
    
    def _test_single_url_param(self, driver, base_url, param, payload):
        """Test single URL parameter with payload"""
        if not driver:
            return None
            
        try:
            parsed = urllib.parse.urlparse(base_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            if query_params:
                new_params = query_params.copy()
                new_params[param] = [payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            else:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            
            # Add small delay to prevent overwhelming the target
            time.sleep(0.1)
            
            detection_result = self._detect_xss_with_driver(driver, test_url, payload, param)
            
            if detection_result['vulnerable']:
                return {
                    'type': 'URL Parameter',
                    'parameter': param,
                    'payload': payload,
                    'url': test_url,
                    'detection_method': detection_result['method'],
                    'evidence': detection_result.get('evidence', '')
                }
        except Exception as e:
            self.log(f"Error testing param {param}: {e}", "debug")
        return None
    
    def _test_single_fragment(self, driver, base_url, payload):
        """Test single URL fragment with payload"""
        if not driver:
            return None
            
        try:
            test_url = f"{base_url}#{urllib.parse.quote(payload)}"
            
            # Add small delay to prevent overwhelming the target
            time.sleep(0.1)
            
            detection_result = self._detect_xss_with_driver(driver, test_url, payload, 'fragment')
            
            if detection_result['vulnerable']:
                return {
                    'type': 'URL Fragment',
                    'payload': payload,
                    'url': test_url,
                    'detection_method': detection_result['method'],
                    'evidence': detection_result.get('evidence', '')
                }
        except Exception as e:
            self.log(f"Error testing fragment: {e}", "debug")
        return None

    def test_url_parameters(self, base_url, payloads):
        """Enhanced URL parameter testing with smart detection"""
        self.log("Testing URL parameters...", "info")
        vulnerabilities = []
        
        parsed = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Smart parameter detection
        test_parameters = ['q', 'search', 'id', 'name', 'query', 'keyword', 'term', 
                          'input', 'data', 'value', 'user', 'username', 'email', 'page']
        
        parameters_to_test = list(query_params.keys()) if query_params else test_parameters[:5]
        
        for param in parameters_to_test:
            self.log(f"Testing parameter: {param}", "debug")
            
            for payload in payloads:
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
                        if payload not in self.vulnerable_payloads:
                            self.vulnerable_payloads.append(payload)
                        self.log(f"✓ XSS found in parameter '{param}' using {detection_result['method']}", "success")
                    
                    # Small delay to avoid rate limiting
                    delay = config.delay / 5 if self.aggressive else config.delay
                    time.sleep(delay)
                            
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    self.log(f"Error testing parameter {param}: {e}", "debug")
        
        return vulnerabilities

    def test_url_fragments(self, base_url, payloads):
        """Enhanced URL fragment testing for DOM-based XSS"""
        self.log("Testing URL fragments for DOM XSS...", "info")
        vulnerabilities = []
        
        for payload in payloads:
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
                    self.log(f"✓ DOM XSS found in fragment", "success")
                
                delay = config.delay / 5 if self.aggressive else config.delay
                time.sleep(delay)
                    
            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.log(f"Error testing fragment: {e}", "debug")
                
        return vulnerabilities

    def test_forms(self, url, payloads):
        """Enhanced form testing with smart recovery"""
        return self._test_forms_with_driver(self.driver, url, payloads)
    
    def _test_forms_with_driver(self, driver, url, payloads):
        """Test forms with specific driver instance"""
        self.log("Testing forms for XSS vulnerabilities...", "info")
        vulnerabilities = []
        
        if not driver:
            return vulnerabilities
            
        try:
            driver.get(url)
            timeout = config.timeout // 2 if self.aggressive else config.timeout
            WebDriverWait(driver, timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Find all forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            self.log(f"Found {len(forms)} form(s) to test", "info")
            
            if not forms:
                return vulnerabilities
                
            for form_idx, form in enumerate(forms):
                self.log(f"Testing form {form_idx + 1}/{len(forms)}", "debug")
                
                # Get all input elements
                inputs = form.find_elements(By.XPATH, 
                    ".//input[@type='text'] | .//input[@type='search'] | .//input[not(@type)] | .//textarea")
                
                if not inputs:
                    self.log(f"No suitable inputs found in form {form_idx + 1}", "debug")
                    continue
                    
                self.log(f"Found {len(inputs)} input field(s) in form {form_idx + 1}", "debug")
                
                for input_idx, inp in enumerate(inputs):
                    input_name = inp.get_attribute("name") or inp.get_attribute("id") or f"input_{input_idx}"
                    self.log(f"Testing input: {input_name}", "debug")
                    
                    # Test with limited payloads
                    for payload in payloads:
                        try:
                            # Navigate back to original page
                            if driver.current_url != url:
                                driver.get(url)
                                WebDriverWait(driver, timeout).until(
                                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                                )
                                forms = driver.find_elements(By.TAG_NAME, "form")
                                if form_idx >= len(forms):
                                    break
                                form = forms[form_idx]
                                inputs = form.find_elements(By.XPATH, 
                                    ".//input[@type='text'] | .//input[@type='search'] | .//input[not(@type)] | .//textarea")
                                if input_idx >= len(inputs):
                                    break
                                inp = inputs[input_idx]
                            
                            # Clear and set payload
                            inp.clear()
                            inp.send_keys(payload)
                            
                            # Try form submission
                            try:
                                form.submit()
                            except:
                                try:
                                    inp.send_keys(Keys.RETURN)
                                except:
                                    pass
                            
                            # Wait and check
                            time.sleep(1)
                            
                            current_url = driver.current_url
                            detection_result = self._detect_xss_with_driver(driver, current_url, payload, f"form_{input_name}")
                            
                            if detection_result['vulnerable']:
                                vuln_info = {
                                    'type': 'Form Input',
                                    'form_index': form_idx,
                                    'input_name': input_name,
                                    'payload': payload,
                                    'url': current_url,
                                    'detection_method': detection_result['method'],
                                    'evidence': detection_result.get('evidence', '')
                                }
                                with self.results_lock:
                                    vulnerabilities.append(vuln_info)
                                self.log(f"✓ XSS found in form input '{input_name}'", "success")
                                break  # Stop testing this input
                            
                            delay = config.delay / 5 if self.aggressive else config.delay
                            time.sleep(delay)
                                
                        except KeyboardInterrupt:
                            raise
                        except Exception as e:
                            self.log(f"Error testing form input: {e}", "debug")
                            # Try to recover
                            try:
                                driver.get(url)
                            except:
                                break
                            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log(f"Form testing error: {e}", "error")
            
        return vulnerabilities

    def test_headers(self, url, payloads):
        """Test XSS through HTTP headers"""
        self.log("Testing HTTP headers...", "info")
        # TODO: Implement header-based XSS testing with requests library
        return []

    def detect_xss_advanced(self, url, payload, context):
        """Enhanced XSS detection with multiple methods (uses self.driver)"""
        return self._detect_xss_with_driver(self.driver, url, payload, context)
    
    def _detect_xss_with_driver(self, driver, url, payload, context):
        """Enhanced XSS detection with multiple methods using specific driver"""
        if not driver:
            return {'vulnerable': False, 'method': 'no_driver'}
            
        detection_result = {
            'vulnerable': False,
            'method': 'none',
            'evidence': ''
        }
        
        try:
            # Navigate to the URL with timeout handling
            try:
                driver.get(url)
                # Small wait for page to stabilize
                time.sleep(0.5)
            except TimeoutException:
                self.log(f"Page load timeout for {context}", "debug")
                return detection_result
            except Exception as e:
                self.log(f"Connection error for {context}: {str(e)[:100]}", "debug")
                return detection_result
            
            # Method 1: Alert-based detection (most reliable)
            try:
                timeout = 1 if self.aggressive else 3
                WebDriverWait(driver, timeout).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                detection_result.update({
                    'vulnerable': True,
                    'method': 'alert_execution',
                    'evidence': f"Alert triggered with text: {alert_text}"
                })
                return detection_result
            except TimeoutException:
                pass  # No alert detected
            except Exception as e:
                self.log(f"Alert check error: {str(e)[:50]}", "debug")
            
            # Method 2: Check for dangerous reflection contexts (only if not aggressive or randomly sample)
            if not self.aggressive or hash(payload) % 5 == 0:  # Sample 20% in aggressive mode
                try:
                    page_source = driver.page_source
                    if payload in page_source:
                        dangerous_contexts = self._check_dangerous_contexts_with_driver(driver, payload)
                        
                        if dangerous_contexts:
                            detection_result.update({
                                'vulnerable': True,
                                'method': 'dangerous_reflection',
                                'evidence': f"Payload in dangerous context: {', '.join(dangerous_contexts)}"
                            })
                            return detection_result
                except Exception as e:
                    self.log(f"Error checking reflection: {str(e)[:50]}", "debug")
                
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log(f"Detection error for {context}: {str(e)[:100]}", "debug")
            
        return detection_result

    def check_dangerous_contexts(self, payload):
        """Check if payload appears in dangerous HTML/JavaScript contexts (uses self.driver)"""
        return self._check_dangerous_contexts_with_driver(self.driver, payload)
    
    def _check_dangerous_contexts_with_driver(self, driver, payload):
        """Check if payload appears in dangerous HTML/JavaScript contexts with specific driver"""
        dangerous_contexts = []
        
        try:
            # Check inside script tags
            scripts = driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                try:
                    script_content = script.get_attribute("innerHTML")
                    if script_content and payload in script_content:
                        dangerous_contexts.append("script_tag")
                        break
                except:
                    pass
            
            # Check in event handlers
            event_attributes = ['onclick', 'onload', 'onerror', 'onmouseover']
            
            for attr in event_attributes:
                try:
                    elements = driver.find_elements(By.XPATH, f"//*[@{attr}]")
                    for element in elements:
                        attr_value = element.get_attribute(attr)
                        if attr_value and payload in attr_value:
                            dangerous_contexts.append(f"event_{attr}")
                            return dangerous_contexts  # Early exit
                except:
                    pass
            
            # Check in href attributes with javascript:
            try:
                links = driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    if href and "javascript:" in href and payload in href:
                        dangerous_contexts.append("javascript_href")
                        break
            except:
                pass
                    
        except Exception as e:
            self.log(f"Error checking dangerous contexts: {e}", "debug")
            
        return dangerous_contexts if dangerous_contexts else None
