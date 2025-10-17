#!/usr/bin/env python3
import asyncio
import aiohttp
import urllib.parse
import re
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from config import config

class XSSScanner:
    def __init__(self, verbose=False):
        self.results = []
        self.session = None
        self.driver_pool = []
        self.lock = threading.Lock()
        self.verbose = verbose
        self.scan_start_time = None

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

    def setup_drivers(self, count=1):
        """Setup browser instances with enhanced options"""
        self.log(f"Setting up {count} browser instance(s)...")
        
        for i in range(count):
            options = Options()
            
            # Enhanced Chrome options for better compatibility
            if config.headless:
                options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-web-security")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument("--disable-features=VizDisplayCompositor")
            options.add_argument(f"--user-agent={config.user_agent}")
            options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
            options.add_experimental_option('useAutomationExtension', False)
            
            # Additional security bypass options
            options.add_argument("--disable-xss-auditor")
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            
            try:
                driver = webdriver.Chrome(options=options)
                driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                driver.set_script_timeout(config.timeout)
                driver.set_page_load_timeout(config.timeout)
                self.driver_pool.append(driver)
                self.log(f"Browser instance {i+1} initialized successfully", "debug")
            except WebDriverException as e:
                self.log(f"WebDriver initialization failed: {e}", "error")
                raise

    def close_drivers(self):
        """Cleanup browser instances"""
        self.log("Closing browser instances...", "debug")
        for driver in self.driver_pool:
            try:
                driver.quit()
            except Exception as e:
                self.log(f"Error closing driver: {e}", "debug")
        self.driver_pool.clear()

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
            self.setup_drivers(count=1)  # Use single driver for stability
            
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
            self.close_drivers()

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
        
        if not self.driver_pool:
            return vulnerabilities
            
        driver = self.driver_pool[0]
        
        try:
            driver.get(url)
            WebDriverWait(driver, config.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Find all forms
            forms = driver.find_elements(By.TAG_NAME, "form")
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
                            original_url = driver.current_url
                            
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
                                from selenium.webdriver.common.keys import Keys
                                inp.send_keys(Keys.RETURN)
                                submitted = True
                            
                            if submitted:
                                # Wait for page load
                                time.sleep(1)
                                
                                # Check for XSS with multiple methods
                                current_url = driver.current_url
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
                            if driver.current_url != original_url:
                                driver.get(original_url)
                                WebDriverWait(driver, config.timeout).until(
                                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                                )
                                
                            # Re-find the form and input
                            forms = driver.find_elements(By.TAG_NAME, "form")
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
                                driver.get(url)
                                WebDriverWait(driver, config.timeout).until(
                                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                                )
                                forms = driver.find_elements(By.TAG_NAME, "form")
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
        if not self.driver_pool:
            return {'vulnerable': False, 'method': 'no_driver'}
            
        driver = self.driver_pool[0]
        detection_result = {
            'vulnerable': False,
            'method': 'none',
            'evidence': ''
        }
        
        try:
            # Navigate to the URL
            driver.get(url)
            
            # Method 1: Alert-based detection (most reliable)
            try:
                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
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
            page_source = driver.page_source
            reflected_locations = self.analyze_reflection(page_source, payload)
            
            if reflected_locations:
                # Check if reflection is in dangerous context
                dangerous_contexts = self.check_dangerous_contexts(driver, payload)
                
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
            dom_vulnerabilities = self.check_dom_xss(driver, payload)
            if dom_vulnerabilities:
                detection_result.update({
                    'vulnerable': True,
                    'method': 'dom_based',
                    'evidence': f"DOM-based XSS detected: {dom_vulnerabilities}"
                })
                return detection_result
                
            # Method 4: Check for JavaScript execution in attributes
            attribute_xss = self.check_attribute_xss(driver, payload)
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
        
        # Clean payload for regex (escape special chars)
        clean_payload = re.escape(payload)
        
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

    def check_dangerous_contexts(self, driver, payload):
        """Check if payload appears in dangerous HTML/JavaScript contexts"""
        dangerous_contexts = []
        
        try:
            # Check inside script tags
            scripts = driver.find_elements(By.TAG_NAME, "script")
            for script in scripts:
                script_content = script.get_attribute("innerHTML")
                if payload in script_content:
                    dangerous_contexts.append("inside_script_tag")
                    break
            
            # Check in event handlers
            event_attributes = ['onclick', 'onload', 'onerror', 'onmouseover', 'onmouseenter', 
                              'onfocus', 'onblur', 'onchange', 'onsubmit']
            
            for attr in event_attributes:
                elements = driver.find_elements(By.XPATH, f"//*[@{attr}]")
                for element in elements:
                    attr_value = element.get_attribute(attr)
                    if attr_value and payload in attr_value:
                        dangerous_contexts.append(f"event_handler_{attr}")
                        break
            
            # Check in href attributes with javascript:
            links = driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                href = link.get_attribute("href")
                if href and "javascript:" in href and payload in href:
                    dangerous_contexts.append("javascript_href")
                    break
            
            # Check in style attributes
            elements_with_style = driver.find_elements(By.XPATH, "//*[@style]")
            for element in elements_with_style:
                style = element.get_attribute("style")
                if style and payload in style:
                    dangerous_contexts.append("style_attribute")
                    break
                    
        except Exception as e:
            self.log(f"Error checking dangerous contexts: {e}", "debug")
            
        return dangerous_contexts if dangerous_contexts else None

    def check_dom_xss(self, driver, payload):
        """Check for DOM-based XSS vulnerabilities"""
        dom_indicators = []
        
        try:
            # Check document.write and similar
            scripts = driver.find_elements(By.TAG_NAME, "script")
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
            if 'location.hash' in driver.page_source or 'location.search' in driver.page_source:
                dom_indicators.append("location_based_dom")
                
        except Exception as e:
            self.log(f"Error checking DOM XSS: {e}", "debug")
            
        return dom_indicators if dom_indicators else None

    def check_attribute_xss(self, driver, payload):
        """Check for XSS in HTML attributes"""
        attribute_vulns = []
        
        try:
            # Check for unquoted attributes that contain our payload
            elements = driver.find_elements(By.XPATH, "//*[@*]")
            
            for element in elements:
                attributes = driver.execute_script(
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
            
        return attribute_vulns if attribute_vulns else None