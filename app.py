"""
Enhanced PDF Tampering Detection Tool - Robust Version
Updated with comprehensive error handling and improved stability
"""

import os
import re
import zlib
from datetime import datetime
from pathlib import Path
import pypdf
import pymupdf
from fuzzywuzzy import fuzz, process
import gradio as gr
import hashlib
import traceback

FUZZYWUZZY_AVAILABLE = True

# Create directories for reports
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

class PDFTamperingDetector:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.results = {}
        self.security_issues = []
        self.tampering_indicators = []
        self.red_flags = []  
        self.console_output = []
        self.analysis_errors = []

        # Whitelist of trusted PDF producers and creators
        self.trusted_producers = [
            "adobe acrobat", "adobe distiller", "acrobat distiller", "acrobat pdfmaker",
            "microsoft print to pdf", "microsoft word", "microsoft excel", "microsoft powerpoint",
            "libreoffice", "openoffice", "latex", "pdftex", "xetex", "luatex",
            "ghostscript", "poppler", "cairo", "webkit", "chrome", "chromium",
            "firefox", "safari", "edge", "prince", "wkhtmltopdf", "pandoc",
            "reportlab", "itext", "tcpdf", "mpdf", "dompdf", "pdflib"
        ]

        # Known PDF editors and suspicious tools
        self.pdf_editors = [
            "smallpdf", "ilovepdf", "sejda", "pdfescape", "sodapdf", "pdf24",
            "cleverpdf", "hipdf", "pdffiller", "formswift", "pdfcandy",
            "combinepdf", "split-pdf", "pdf-merger", "pdfresizer",
            "foxit", "nitro", "wondershare", "pdfxchange", "cute pdf",
            "bullzip", "deskpdf", "novapdf", "pdf creator", "primopdf",
            "crack", "keygen", "patch", "activator", "serial", "pirate",
            "warez", "nulled", "hack", "mod", "cracked", "free download",
            "pypdf", "unknown", "modified", "edited", "processed", "converted",
            "generated", "created", "temp", "anonymous"
        ]

        self.editor_risk_levels = {
            "online": ["smallpdf", "ilovepdf", "sejda", "pdfescape", "sodapdf",
                      "pdf24", "cleverpdf", "hipdf", "pdffiller", "formswift",
                      "pdfcandy", "combinepdf", "split-pdf", "pdf-merger", "pdfresizer"],
            "suspicious": ["crack", "keygen", "patch", "activator", "serial",
                           "pirate", "warez", "nulled", "hack", "mod", "cracked"],
            "programmatic": ["pypdf", "reportlab", "pdfkit", "wkhtmltopdf",
                             "latex", "tex", "ghostscript", "itext", "tcpdf"]
        }

        # Initialize temp files list for cleanup
        self.temp_files = []

    def __del__(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except Exception:
                pass  # Ignore cleanup errors

    def log(self, message):
        """Log message for UI display"""
        self.console_output.append(message)
        print(message)

    def safe_execute(self, func, error_message, *args, **kwargs):
        """Safely execute a function with error handling"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.log(f"❌ {error_message}: {str(e)}")
            self.analysis_errors.append(f"{error_message}: {str(e)}")
            return None

    def safe_get_object(self, reader, obj_ref):
        """Safely get PDF object with error handling"""
        try:
            if obj_ref is None:
                return None
            obj = reader.get_object(obj_ref)
            return obj
        except Exception as e:
            self.log(f"   ⚠️ Error getting object: {e}")
            return None

    def safe_get_indirect_reference(self, obj):
        """Safely get indirect reference with error handling"""
        try:
            if obj is None:
                return None
            if hasattr(obj, 'indirect_reference'):
                return obj.indirect_reference
            else:
                return None
        except Exception:
            return None

    def validate_pdf_file(self):
        """Validate that the file exists and is a valid PDF"""
        try:
            # Check file existence
            if not os.path.exists(self.pdf_path):
                self.log("❌ ERROR: File does not exist")
                return False

            # Check file size
            file_size = os.path.getsize(self.pdf_path)
            if file_size == 0:
                self.log("❌ ERROR: File is empty")
                return False

            if file_size > 500 * 1024 * 1024:  # 500MB limit
                self.log(f"⚠️ WARNING: Very large file ({file_size:,} bytes)")

            # Check PDF header
            with open(self.pdf_path, 'rb') as f:
                header = f.read(8)
                if not header.startswith(b'%PDF-'):
                    self.log("❌ ERROR: Not a valid PDF file")
                    return False

            # Try to open with both libraries
            try:
                doc = pymupdf.open(self.pdf_path)
                doc.close()
            except Exception as e:
                self.log(f"⚠️ WARNING: PyMuPDF cannot open file: {e}")

            try:
                reader = pypdf.PdfReader(self.pdf_path)
                if reader.is_encrypted and reader.needs_pass:
                    self.log("⚠️ WARNING: File is password protected, some analysis may be limited")
            except Exception as e:
                self.log(f"⚠️ WARNING: PyPDF cannot open file: {e}")

            return True

        except Exception as e:
            self.log(f"❌ ERROR: Cannot validate file: {e}")
            return False

    def analyze_pdf(self):
        self.log("=" * 60)
        self.log(f"PDF SECURITY ANALYSIS")
        self.log(f"File: {self.pdf_path}")
        self.log(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log("=" * 60)

        # Validate file first
        if not self.validate_pdf_file():
            self.results['error'] = "Invalid or inaccessible PDF file"
            self.results['console_output'] = self.console_output
            return self.results

        # Run analysis methods with individual error handling
        analysis_methods = [
            (self._extract_comprehensive_metadata, "metadata extraction"),
            (self._check_signatures, "signature analysis"),
            (self._check_encryption, "encryption analysis"),
            (self._find_embedded_files, "embedded files analysis"),
            (self._extract_images, "image analysis"),
            (self._check_incremental_updates, "incremental updates analysis"),
            (self._extract_javascript, "JavaScript analysis"),
            (self._analyze_xref_structure, "cross-reference analysis"),
            (self._check_for_orphaned_objects, "orphaned objects analysis"),
            (self._compute_file_hash, "file hash computation"),
            (self._generate_security_summary, "security summary"),
            (self._generate_final_verdict, "final verdict")
        ]

        for method, description in analysis_methods:
            try:
                self.log(f"\n🔄 Starting {description}...")
                method()
                self.log(f"✅ Completed {description}")
            except Exception as e:
                error_msg = f"Error in {description}"
                self.log(f"❌ {error_msg}: {str(e)}")
                self.analysis_errors.append(f"{error_msg}: {str(e)}")
                
                # Log detailed error for debugging
                if hasattr(e, '__traceback__'):
                    tb_str = ''.join(traceback.format_tb(e.__traceback__))
                    self.log(f"   Debug trace: {tb_str}")

        # Store analysis errors in results
        self.results['analysis_errors'] = self.analysis_errors
        self.results['console_output'] = self.console_output
        return self.results

    def _parse_pdf_date(self, pdf_date: str) -> str:
        """Safely parse PDF date format"""
        try:
            if not pdf_date or not isinstance(pdf_date, str):
                return str(pdf_date) if pdf_date else "Unknown"

            if not pdf_date.startswith("D:"):
                return pdf_date

            pdf_date = pdf_date[2:]
            date_str = pdf_date[:14]

            dt = datetime.strptime(date_str, "%Y%m%d%H%M%S")
            tz_match = re.search(r"([+-])(\d{2})'(\d{2})", pdf_date)
            if tz_match:
                sign, hours, minutes = tz_match.groups()
                tz_str = f"UTC{sign}{hours}:{minutes}"
            else:
                tz_str = "UTC"
            return dt.strftime("%B %d, %Y at %I:%M %p") + f" ({tz_str})"
        except Exception as e:
            self.log(f"   ⚠️ Error parsing date '{pdf_date}': {e}")
            return str(pdf_date) if pdf_date else "Unknown"

    def _extract_comprehensive_metadata(self):
        self.log("\nMETADATA ANALYSIS")
        self.log("-" * 30)

        # Initialize comprehensive metadata structure
        comprehensive_meta = {
            'format': 'PDF',
            'title': None,
            'author': None,
            'creator': None,
            'producer': None,
            'creation_date': None,
            'modification_date': None,
            'subject': None,
            'keywords': None
        }

        try:
            doc = pymupdf.open(self.pdf_path)
            meta = doc.metadata or {}
            doc.close()

            if not meta or all(v is None or v == "" for v in meta.values()):
                self.log("WARNING: No metadata found - This could indicate tampering or sanitization")
                self.red_flags.append("Missing metadata may indicate document sanitization")
            else:
                self.log("Metadata found:")
                
                # Map metadata fields safely
                for key in comprehensive_meta.keys():
                    if key == 'format':
                        comprehensive_meta[key] = 'PDF'
                    elif key in meta and meta[key]:
                        if 'date' in key.lower():
                            comprehensive_meta[key] = self._parse_pdf_date(meta[key])
                        else:
                            comprehensive_meta[key] = str(meta[key])

                # Handle alternative field names
                if not comprehensive_meta['creation_date'] and meta.get('creationDate'):
                    comprehensive_meta['creation_date'] = self._parse_pdf_date(meta['creationDate'])
                if not comprehensive_meta['modification_date'] and meta.get('modDate'):
                    comprehensive_meta['modification_date'] = self._parse_pdf_date(meta['modDate'])

                # Display found metadata
                for k, v in comprehensive_meta.items():
                    if v:
                        self.log(f"   • {k.replace('_', ' ').title()}: {v}")

                # Check for missing mandatory fields
                mandatory_fields = ['title', 'author', 'creator', 'producer', 'creation_date']
                missing_fields = [field for field in mandatory_fields if not comprehensive_meta.get(field)]
                
                if missing_fields:
                    self.log(f"WARNING: Missing mandatory metadata fields: {', '.join(missing_fields)}")
                    self.tampering_indicators.append(f"Missing mandatory metadata: {', '.join(missing_fields)}")

                # Check date consistency
                if (comprehensive_meta.get('creation_date') and 
                    comprehensive_meta.get('modification_date') and
                    comprehensive_meta['creation_date'] != comprehensive_meta['modification_date']):
                    self.log("RED FLAG: Creation date and modification date differ")
                    self.red_flags.append("Document has been modified after creation")

                # Analyze producer and creator with whitelist
                self._analyze_producer_with_whitelist(
                    comprehensive_meta.get('producer', ''), 
                    comprehensive_meta.get('creator', '')
                )

        except Exception as e:
            self.log(f"❌ Error extracting metadata: {e}")
            self.red_flags.append("Could not extract metadata - file may be corrupted")

        self.results['comprehensive_metadata'] = comprehensive_meta

    def _analyze_producer_with_whitelist(self, producer, creator):
        self.log("\nPRODUCER/CREATOR SECURITY ANALYSIS")
        self.log("-" * 30)

        if not producer and not creator:
            self.log("WARNING: No producer or creator information found")
            self.red_flags.append("Missing producer/creator information")
            return

        tools_to_check = []
        if producer:
            tools_to_check.append(('Producer', str(producer)))
        if creator:
            tools_to_check.append(('Creator', str(creator)))

        for tool_type, tool_name in tools_to_check:
            try:
                self.log(f"{tool_type}: {tool_name}")
                
                # Check against whitelist first
                is_trusted = self._check_against_whitelist(tool_name)
                
                if is_trusted:
                    self.log(f"   ✅ {tool_type} is from a trusted source")
                else:
                    self.log(f"   ⚠️ {tool_type} is not in trusted whitelist")
                    
                    # Use fuzzy matching with higher threshold (90%)
                    if FUZZYWUZZY_AVAILABLE:
                        self._enhanced_fuzzy_match_producer(tool_type, tool_name)
                    else:
                        self._basic_match_producer(tool_type, tool_name)
            except Exception as e:
                self.log(f"   ⚠️ Error analyzing {tool_type}: {e}")

    def _check_against_whitelist(self, tool_name):
        """Check if the tool is in the trusted whitelist"""
        try:
            if not tool_name:
                return False
                
            tool_lower = str(tool_name).lower()
            
            # Direct check
            for trusted in self.trusted_producers:
                if trusted in tool_lower or tool_lower in trusted:
                    return True
            
            # Fuzzy check against whitelist with high threshold
            if FUZZYWUZZY_AVAILABLE:
                matches = process.extract(tool_lower, self.trusted_producers, limit=1, scorer=fuzz.partial_ratio)
                if matches and matches[0][1] >= 85:  # High confidence for whitelist
                    return True
            
            return False
        except Exception:
            return False

    def _enhanced_fuzzy_match_producer(self, tool_type, tool_name):
        try:
            tool_lower = str(tool_name).lower()
            matches = process.extract(tool_lower, self.pdf_editors, limit=3, scorer=fuzz.partial_ratio)
            
            # Only flag if similarity is > 90%
            high_confidence_matches = [m for m in matches if m[1] >= 90]
            
            if high_confidence_matches:
                self.log(f"   🚨 HIGH CONFIDENCE SUSPICIOUS MATCHES (>90% similarity):")
                for match, confidence in high_confidence_matches:
                    risk_level = self._get_tool_risk_level(match)
                    self.log(f"      • {match} (confidence: {confidence}%) - {risk_level}")
                    if risk_level == "HIGH RISK":
                        self.red_flags.append(f"{tool_type} indicates high-risk tool: {match}")
                    elif "SUSPICIOUS" in risk_level or "ONLINE" in risk_level:
                        self.tampering_indicators.append(f"{tool_type} indicates editing tool: {match}")
            else:
                # Check for direct substring matches
                direct_matches = [editor for editor in self.pdf_editors if editor in tool_lower]
                if direct_matches:
                    self.log(f"   ⚠️ DIRECT MATCHES FOUND:")
                    for match in direct_matches:
                        risk_level = self._get_tool_risk_level(match)
                        self.log(f"      • {match} - {risk_level}")
                        if risk_level == "HIGH RISK":
                            self.red_flags.append(f"{tool_type} contains suspicious keywords: {match}")
        except Exception as e:
            self.log(f"   ⚠️ Error in fuzzy matching: {e}")

    def _basic_match_producer(self, tool_type, tool_name):
        try:
            tool_lower = str(tool_name).lower()
            matches_found = [editor for editor in self.pdf_editors if editor in tool_lower]

            if matches_found:
                self.log(f"   ⚠️ POTENTIAL MATCHES FOUND:")
                for match in matches_found:
                    risk_level = self._get_tool_risk_level(match)
                    self.log(f"      • {match} - {risk_level}")
                    if risk_level == "HIGH RISK":
                        self.red_flags.append(f"{tool_type} indicates high-risk tool: {match}")
        except Exception as e:
            self.log(f"   ⚠️ Error in basic matching: {e}")

    def _get_tool_risk_level(self, tool_name):
        try:
            tool_lower = str(tool_name).lower()
            if any(s in tool_lower for s in self.editor_risk_levels["suspicious"]):
                return "HIGH RISK"
            elif any(o in tool_lower for o in self.editor_risk_levels["online"]):
                return "MEDIUM-HIGH RISK (Online Tool)"
            elif any(p in tool_lower for p in self.editor_risk_levels["programmatic"]):
                return "MEDIUM RISK (Programmatic)"
            else:
                return "LOW-MEDIUM RISK"
        except Exception:
            return "UNKNOWN RISK"

    def _check_signatures(self):
        self.log("\nDIGITAL SIGNATURE ANALYSIS")
        self.log("-" * 30)

        try:
            doc = pymupdf.open(self.pdf_path)
            sigs = doc.get_sigflags()
            doc.close()

            if sigs == 0:
                self.log("ℹ️ No digital signatures found")
                self.results['signatures'] = "No signatures"
            elif sigs == 1:
                self.log("⚠️ Unsigned signature fields detected")
                self.tampering_indicators.append("Unsigned signature fields present")
                self.results['signatures'] = "Unsigned fields present"
            elif sigs == 3:
                self.log("✅ Document contains valid digital signatures")
                self.results['signatures'] = "Digitally signed"
            else:
                self.log(f"⚠️ Unknown signature flag: {sigs}")
                self.tampering_indicators.append(f"Unusual signature flag: {sigs}")
                self.results['signatures'] = f"Unknown flag: {sigs}"
        except Exception as e:
            self.log(f"❌ Error checking signatures: {e}")
            self.results['signatures'] = "Analysis failed"

    def _check_encryption(self):
        self.log("\nENCRYPTION ANALYSIS")
        self.log("-" * 30)

        try:
            doc = pymupdf.open(self.pdf_path)
            is_encrypted = doc.is_encrypted
            needs_pass = doc.needs_pass
            doc.close()

            if is_encrypted:
                self.log("🚨 RED FLAG: Document is encrypted")
                self.red_flags.append("Document uses encryption (potential security concern)")
                if needs_pass:
                    self.log("🔒 Document is password-protected")
                    self.results['encryption'] = "Password protected"
                else:
                    self.log("⚠️ Document is encrypted but opened without password")
                    self.red_flags.append("Weak encryption detected")
                    self.results['encryption'] = "Weak encryption"
            else:
                self.log("✅ Document is not encrypted")
                self.results['encryption'] = "Not encrypted"
        except Exception as e:
            self.log(f"❌ Error checking encryption: {e}")
            self.results['encryption'] = "Analysis failed"

    def _find_embedded_files(self):
        self.log("\nEMBEDDED FILES ANALYSIS")
        self.log("-" * 30)

        try:
            doc = pymupdf.open(self.pdf_path)
            count = doc.embfile_count()

            if count == 0:
                self.log("✅ No embedded files found")
                self.results['embedded_files'] = []
            else:
                self.log(f"🚨 RED FLAG: Found {count} embedded file(s)")
                self.red_flags.append(f"Document contains {count} embedded files")
                embedded_files = []
                total_size = 0
                
                for i in range(count):
                    try:
                        info = doc.embfile_info(i)
                        if info:
                            fname = info.get("filename", f"embedded_file_{i}")
                            data = doc.embfile_get(i)
                            size = len(data) if data else 0
                            total_size += size
                            self.log(f"   • {fname} ({size} bytes)")
                            embedded_files.append({'name': fname, 'size': size})
                            
                            ext = os.path.splitext(fname)[1].lower()
                            if ext in ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js']:
                                self.red_flags.append(f"Potentially malicious embedded file: {fname}")
                    except Exception as e:
                        self.log(f"   ⚠️ Error processing embedded file {i}: {e}")
                        
                self.results['embedded_files'] = embedded_files
                self.results['embedded_total_size'] = total_size
            doc.close()
        except Exception as e:
            self.log(f"❌ Error checking embedded files: {e}")
            self.results['embedded_files'] = []

    def _extract_images(self):
        self.log("\nIMAGE ANALYSIS")
        self.log("-" * 30)

        try:
            doc = pymupdf.open(self.pdf_path)
            image_count = 0
            
            for page in doc:
                try:
                    images = page.get_images(full=True)
                    image_count += len(images)
                except Exception as e:
                    self.log(f"   ⚠️ Error processing page images: {e}")
                    
            if image_count == 0:
                self.log("ℹ️ No images found")
            else:
                self.log(f"ℹ️ Found {image_count} image(s) across {len(doc)} page(s)")
                
            self.results['image_count'] = image_count
            doc.close()
        except Exception as e:
            self.log(f"❌ Error analyzing images: {e}")
            self.results['image_count'] = 0

    def _check_incremental_updates(self):
        self.log("\nINCREMENTAL UPDATES ANALYSIS")
        self.log("-" * 30)

        try:
            with open(self.pdf_path, "rb") as f:
                content = f.read()
                
            startxrefs = []
            for match in re.finditer(b"startxref\s*(\d+)", content):
                try:
                    startxrefs.append(int(match.group(1)))
                except ValueError:
                    continue
                    
            if not startxrefs:
                self.log("❌ No startxref markers found - File may be corrupted")
                self.red_flags.append("Missing startxref markers")
                self.results['incremental_updates'] = "No markers found"
                return

            update_count = len(startxrefs) - 1
            if update_count == 0:
                self.log("✅ No incremental updates detected")
            else:
                self.log(f"🚨 RED FLAG: Found {update_count} incremental update(s)")
                self.red_flags.append(f"Document has {update_count} incremental updates (indicates modification)")
                for i, offset in enumerate(reversed(startxrefs)):
                    ver = len(startxrefs) - i
                    self.log(f"   • Version {ver}: starts at byte {offset}")
                    
            self.results['incremental_updates'] = update_count
        except Exception as e:
            self.log(f"❌ Error checking incremental updates: {e}")
            self.results['incremental_updates'] = "Analysis failed"

    def _extract_javascript(self):
        self.log("\nJAVASCRIPT ANALYSIS")
        self.log("-" * 30)

        js_payloads = []
        
        try:
            reader = pypdf.PdfReader(self.pdf_path)
            
            for xref in reader.xref:
                for obj_id in reader.xref[xref]:
                    try:
                        obj = self.safe_get_object(reader, obj_id)
                        
                        # Check if obj is None before accessing attributes
                        if obj is None:
                            continue
                            
                        if (isinstance(obj, pypdf.generic.DictionaryObject) and 
                            obj.get("/S") == "/JavaScript"):
                            
                            if "/JS" in obj:
                                js_ref = obj["/JS"]
                                
                                # Check if js_ref is valid before getting object
                                if js_ref is None:
                                    continue
                                    
                                try:
                                    js_obj = self.safe_get_object(reader, js_ref)
                                    
                                    # Check if js_obj is None
                                    if js_obj is None:
                                        continue
                                        
                                    code = b""
                                    if isinstance(js_obj, pypdf.generic.EncodedStreamObject):
                                        if js_obj.get("/Filter") == "/FlateDecode":
                                            try:
                                                code = zlib.decompress(js_obj.get_data())
                                            except zlib.error as e:
                                                self.log(f"   ⚠️ Failed to decompress JavaScript: {e}")
                                                continue
                                        else:
                                            code = js_obj.get_data()
                                    elif isinstance(js_obj, (pypdf.generic.TextStringObject, pypdf.generic.ByteStringObject)):
                                        code = str(js_obj).encode("utf-8", errors="ignore")
                                        
                                    if code:
                                        try:
                                            js_code = code.decode("utf-8", errors="replace")
                                            js_payloads.append(js_code)
                                            
                                            # Check for malicious patterns
                                            malicious_patterns = ['eval(', 'document.write', 'unescape', 'fromcharcode', 'activex']
                                            if any(pattern in js_code.lower() for pattern in malicious_patterns):
                                                self.red_flags.append("Potentially malicious JavaScript detected")
                                        except UnicodeDecodeError as e:
                                            self.log(f"   ⚠️ Failed to decode JavaScript: {e}")
                                            
                                except Exception as e:
                                    self.log(f"   ⚠️ Error processing JavaScript reference: {e}")
                                    continue
                                    
                    except Exception as e:
                        self.log(f"   ⚠️ Error processing object {obj_id}: {e}")
                        continue
            
            # Log results
            if js_payloads:
                self.log(f"🚨 RED FLAG: Found {len(js_payloads)} JavaScript payload(s)")
                self.red_flags.append(f"Document contains {len(js_payloads)} JavaScript payloads")
                for i, code in enumerate(js_payloads, 1):
                    self.log(f"   • Payload {i}: {len(code)} characters")
                    if len(code) < 200:
                        self.log(f"     Preview: {code[:100]}...")
            else:
                self.log("✅ No JavaScript found")

        except Exception as e:
            self.log(f"❌ Error during JavaScript analysis: {e}")
            self.security_issues.append(f"JavaScript analysis failed: {str(e)}")

        self.results['javascript_count'] = len(js_payloads)
        self.results['javascript_payloads'] = js_payloads

    def _analyze_xref_structure(self):
        self.log("\nCROSS-REFERENCE TABLE ANALYSIS")
        self.log("-" * 30)

        try:
            doc = pymupdf.open(self.pdf_path)
            xref_count = doc.xref_length()
            stream_objects = 0
            non_stream_objects = 0

            for xref in range(1, xref_count):
                try:
                    if doc.xref_is_stream(xref):
                        stream_objects += 1
                    else:
                        non_stream_objects += 1
                except Exception:
                    continue

            total_objects = xref_count - 1
            self.log(f"ℹ️ Cross-reference analysis:")
            self.log(f"   • Total objects: {total_objects}")
            self.log(f"   • Stream objects: {stream_objects}")
            self.log(f"   • Non-stream objects: {non_stream_objects}")

            self.results['xref_total'] = total_objects
            self.results['xref_streams'] = stream_objects
            doc.close()
        except Exception as e:
            self.log(f"❌ Error analyzing cross-reference structure: {e}")
            self.results['xref_total'] = 0
            self.results['xref_streams'] = 0

    def _check_for_orphaned_objects(self):
        self.log("\nORPHANED OBJECTS ANALYSIS")
        self.log("-" * 30)

        try:
            original_size = os.path.getsize(self.pdf_path)
            temp_output = f"temp_optimized_{os.getpid()}.pdf"
            self.temp_files.append(temp_output)
            
            # Add error handling for PDF operations
            try:
                writer = pypdf.PdfWriter(clone_from=self.pdf_path)
                writer.compress_identical_objects(remove_orphans=True)
                
                with open(temp_output, "wb") as f:
                    writer.write(f)
                    
            except Exception as e:
                self.log(f"❌ Error during PDF optimization: {e}")
                self.security_issues.append(f"Could not analyze orphaned objects: {str(e)}")
                self.results['original_size'] = original_size
                self.results['optimization_reduction'] = 0
                return

            if not os.path.exists(temp_output):
                self.log("❌ Optimization failed - could not create temporary file")
                self.results['original_size'] = original_size
                self.results['optimization_reduction'] = 0
                return

            optimized_size = os.path.getsize(temp_output)
            size_difference = original_size - optimized_size
            percent_reduction = (size_difference / original_size) * 100 if original_size > 0 else 0

            self.log(f"ℹ️ File size analysis:")
            self.log(f"   • Original size: {original_size:,} bytes")
            self.log(f"   • Optimized size: {optimized_size:,} bytes")
            self.log(f"   • Size difference: {size_difference:,} bytes ({percent_reduction:.1f}%)")

            # Check if orphaned objects are outside acceptable range (-10% to +10%)
            if percent_reduction > 10:
                self.log("🚨 RED FLAG: Excessive orphaned objects detected")
                self.red_flags.append(f"High redundancy detected ({percent_reduction:.1f}% optimization possible)")
            elif percent_reduction < -10:
                self.log("🚨 RED FLAG: Unusual negative optimization")
                self.red_flags.append(f"Unusual file structure (negative optimization: {percent_reduction:.1f}%)")
            else:
                self.log("✅ Orphaned objects within acceptable range")

            self.results['original_size'] = original_size
            self.results['optimization_reduction'] = percent_reduction

        except Exception as e:
            self.log(f"❌ Error during orphaned objects analysis: {e}")
            self.security_issues.append(f"Orphaned objects analysis failed: {str(e)}")
            self.results['original_size'] = 0
            self.results['optimization_reduction'] = 0

    def _compute_file_hash(self):
        """Compute SHA-256 hash of the PDF file."""
        try:
            hash_sha256 = hashlib.sha256()
            with open(self.pdf_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            file_hash = hash_sha256.hexdigest()
            self.results['file_hash_sha256'] = file_hash
            self.log(f"📄 File SHA-256 hash: {file_hash}")
            return file_hash
        except Exception as e:
            self.log(f"❌ Failed to compute file hash: {e}")
            self.results['file_hash_sha256'] = None
            return None

    def _generate_final_verdict(self):
        """Generate a simple, user-friendly final verdict"""
        self.log("\n" + "=" * 60)
        self.log("FINAL SECURITY VERDICT")
        self.log("=" * 60)

        verdict_items = []
        
        # Check each requirement
        meta = self.results.get('comprehensive_metadata', {})
        
        # 1. Complete metadata check
        mandatory_fields = ['title', 'author', 'creator', 'producer', 'creation_date']
        missing_fields = [field for field in mandatory_fields if not meta.get(field)]
        if missing_fields:
            verdict_items.append(f"❌ Missing important document information: {', '.join(missing_fields)}")
        else:
            verdict_items.append("✅ All required document information is present")

        # 2. Date consistency check
        if meta.get('creation_date') and meta.get('modification_date'):
            if meta['creation_date'] == meta['modification_date']:
                verdict_items.append("✅ Document dates are consistent")
            else:
                verdict_items.append("❌ Document was modified after creation")
        else:
            verdict_items.append("⚠️ Cannot verify document date consistency")

        # 3. Incremental updates check
        incremental_updates = self.results.get('incremental_updates', 0)
        if incremental_updates == 0:
            verdict_items.append("✅ Document has not been incrementally modified")
        elif isinstance(incremental_updates, str):
            verdict_items.append("⚠️ Could not verify document modification history")
        else:
            verdict_items.append(f"❌ Document has been modified {incremental_updates} time(s)")

        # 4. Producer/Creator whitelist check
        producer_trusted = self._check_against_whitelist(meta.get('producer', ''))
        creator_trusted = self._check_against_whitelist(meta.get('creator', ''))
        if producer_trusted or creator_trusted:
            verdict_items.append("✅ Document created by trusted software")
        else:
            verdict_items.append("❌ Document created by untrusted or unknown software")

        # 5. JavaScript check
        js_count = self.results.get('javascript_count', 0)
        if js_count == 0:
            verdict_items.append("✅ No executable code found in document")
        else:
            verdict_items.append(f"❌ Document contains {js_count} executable script(s)")

        # 6. Encryption check
        encryption = self.results.get('encryption', '')
        if encryption == "Not encrypted":
            verdict_items.append("✅ Document is not encrypted")
        else:
            verdict_items.append(f"❌ Document uses encryption: {encryption}")

        # 7. Embedded files check
        embedded_count = len(self.results.get('embedded_files', []))
        if embedded_count == 0:
            verdict_items.append("✅ No hidden files embedded in document")
        else:
            verdict_items.append(f"❌ Document contains {embedded_count} embedded file(s)")

        # 8. Orphaned objects check
        optimization = self.results.get('optimization_reduction', 0)
        if isinstance(optimization, (int, float)) and -10 <= optimization <= 10:
            verdict_items.append("✅ Document structure appears normal")
        else:
            verdict_items.append(f"❌ Unusual document structure detected")

        # Calculate overall verdict
        red_flag_count = len(self.red_flags)
        failed_checks = len([item for item in verdict_items if item.startswith("❌")])
        
        if red_flag_count >= 3 or failed_checks >= 4:
            overall_verdict = "🔴 HIGH RISK - Do not trust this document"
            verdict_explanation = "This document shows multiple signs of tampering or suspicious creation. It may be dangerous to open or trust."
        elif red_flag_count >= 1 or failed_checks >= 2:
            overall_verdict = "🟡 MEDIUM RISK - Exercise caution"
            verdict_explanation = "This document has some suspicious characteristics. Verify its source before trusting its contents."
        else:
            overall_verdict = "🟢 LOW RISK - Document appears trustworthy"
            verdict_explanation = "This document passes most security checks and appears to be legitimate."

        self.log(f"\n{overall_verdict}")
        self.log(f"{verdict_explanation}")
        self.log("\nDetailed Checks:")
        for item in verdict_items:
            self.log(f"  {item}")

        # Include analysis errors in verdict if any
        if self.analysis_errors:
            self.log(f"\n⚠️ Note: {len(self.analysis_errors)} analysis error(s) occurred during scanning")
            verdict_explanation += f" Note: Some analysis components failed ({len(self.analysis_errors)} errors)."

        # Store results
        self.results['final_verdict'] = {
            'overall': overall_verdict,
            'explanation': verdict_explanation,
            'detailed_checks': verdict_items,
            'red_flag_count': red_flag_count,
            'failed_checks': failed_checks
        }

    def _generate_security_summary(self):
        self.log("\n" + "=" * 60)
        self.log("SECURITY ASSESSMENT SUMMARY")
        self.log("=" * 60)
        
        risk_level = self._calculate_risk_level()
        self.log(f"OVERALL RISK LEVEL: {risk_level}\n")

        if self.red_flags:
            self.log("🚨 CRITICAL SECURITY FLAGS:")
            for i, flag in enumerate(self.red_flags, 1):
                self.log(f"   {i}. {flag}")
            self.log("")

        if self.security_issues:
            self.log("⚠️ SECURITY ISSUES DETECTED:")
            for i, issue in enumerate(self.security_issues, 1):
                self.log(f"   {i}. {issue}")
            self.log("")
        
        if self.tampering_indicators:
            self.log("ℹ️ POTENTIAL TAMPERING INDICATORS:")
            for i, indicator in enumerate(self.tampering_indicators, 1):
                self.log(f"   {i}. {indicator}")
            self.log("")

        if self.analysis_errors:
            self.log("🔧 ANALYSIS ERRORS:")
            for i, error in enumerate(self.analysis_errors, 1):
                self.log(f"   {i}. {error}")
            self.log("")

        self._generate_recommendations(risk_level)

    def _calculate_risk_level(self):
        risk_score = 0
        risk_score += len(self.red_flags) * 5  # Red flags are more serious
        risk_score += len(self.security_issues) * 3
        risk_score += len(self.tampering_indicators) * 1
        risk_score += len(self.analysis_errors) * 2  # Analysis errors increase risk

        self.results['risk_score'] = risk_score
        self.results['red_flags'] = self.red_flags
        self.results['security_issues'] = self.security_issues
        self.results['tampering_indicators'] = self.tampering_indicators

        if risk_score >= 15:
            return "🔴 CRITICAL RISK"
        elif risk_score >= 10:
            return "🔴 HIGH RISK"
        elif risk_score >= 6:
            return "🟡 MEDIUM-HIGH RISK"
        elif risk_score >= 3:
            return "🟠 MEDIUM RISK"
        elif risk_score >= 1:
            return "🟡 LOW-MEDIUM RISK"
        else:
            return "🟢 LOW RISK"

    def _generate_recommendations(self, risk_level):
        self.log("💡 RECOMMENDATIONS:")
        recommendations = []
        
        if "CRITICAL" in risk_level or "HIGH RISK" in risk_level:
            recs = [
                "Do NOT open this PDF in a standard viewer",
                "Consider this PDF potentially dangerous",
                "Use a sandboxed environment if analysis is required",
                "Verify the document source immediately"
            ]
        elif "MEDIUM" in risk_level:
            recs = [
                "Exercise extreme caution when opening this PDF",
                "Use a secure PDF viewer with JavaScript disabled",
                "Verify the document source before trusting content",
                "Consider scanning for malware"
            ]
        else:
            recs = [
                "Document appears relatively safe",
                "Standard security precautions should suffice",
                "Keep antivirus software updated"
            ]

        if self.analysis_errors:
            recs.append("Re-run analysis with a different tool to verify results")

        for rec in recs:
            if "CRITICAL" in risk_level or "HIGH RISK" in risk_level:
                self.log(f"   ⚠️ {rec}")
            elif "MEDIUM" in risk_level:
                self.log(f"   ⚠️ {rec}")
            else:
                self.log(f"   ✅ {rec}")
            recommendations.append(rec)

        self.results['recommendations'] = recommendations
        self.results['overall_risk_level'] = risk_level

# Gradio Interface Functions (unchanged from your original code)
def analyze_pdf_gradio(file_path):
    """Main analysis function for Gradio interface"""
    if not file_path:
        return "❌ No file uploaded", "", "", "", ""
    
    if not file_path.endswith('.pdf'):
        return "❌ Please upload a PDF file only", "", "", "", ""
    
    # Run analysis
    detector = PDFTamperingDetector(file_path)
    results = detector.analyze_pdf()
    
    # Format results for display
    console_output = "\n".join(results.get('console_output', []))
    
    # Create summary
    summary = create_summary(results)
    
    # Create metadata display
    metadata_display = create_metadata_display(results)
    
    # Create security details
    security_details = create_security_details(results)
    
    # Create final verdict
    final_verdict = create_final_verdict(results)
    
    return summary, metadata_display, security_details, console_output, final_verdict

def create_summary(results):
    """Create simplified, user-friendly summary"""
    risk_level = results.get('overall_risk_level', 'Unknown')
    red_flags_count = len(results.get('red_flags', []))
    analysis_errors = len(results.get('analysis_errors', []))
    
    # Simplified risk explanation
    if "CRITICAL" in risk_level or "HIGH RISK" in risk_level:
        risk_explanation = "This document appears dangerous and should not be trusted."
    elif "MEDIUM" in risk_level:
        risk_explanation = "This document has suspicious elements. Use caution."
    else:
        risk_explanation = "This document appears to be safe."
    
    summary = f"""## Security Assessment

**Risk Level:** {risk_level}
**Assessment:** {risk_explanation}

### Key Issues Found:
"""
    
    # Show critical flags first
    if results.get('red_flags'):
        summary += "\n**Critical Security Concerns:**\n"
        for flag in results['red_flags'][:5]:  # Limit to top 5
            summary += f"- {flag}\n"
    
    # Show other issues
    if results.get('security_issues'):
        summary += "\n**Security Issues:**\n"
        for issue in results['security_issues'][:3]:  # Limit to top 3
            summary += f"- {issue}\n"

    # Show analysis errors if any
    if analysis_errors > 0:
        summary += f"\n**Analysis Note:** {analysis_errors} component(s) failed during analysis\n"
    
    if not results.get('red_flags') and not results.get('security_issues'):
        summary += "\n- No major security issues detected\n"
    
    return summary

def create_metadata_display(results):
    """Create comprehensive metadata display"""
    meta = results.get('comprehensive_metadata', {})
    
    if not meta or all(v is None or v == "" for v in meta.values() if v != 'PDF'):
        return "❌ No metadata found - This could indicate tampering or sanitization"
    
    display = "## Complete Document Information\n\n"
    
    # Display all metadata fields
    field_labels = {
        'format': 'Document Format',
        'title': 'Title',
        'author': 'Author',
        'creator': 'Creator Software',
        'producer': 'Producer Software',
        'creation_date': 'Creation Date',
        'modification_date': 'Modification Date',
        'subject': 'Subject',
        'keywords': 'Keywords'
    }
    
    for field, label in field_labels.items():
        value = meta.get(field, 'Not specified')
        if value:
            display += f"**{label}:** {value}\n\n"
        else:
            display += f"**{label}:** *Not specified*\n\n"
    
    return display

def create_security_details(results):
    """Create detailed security analysis"""
    details = "## Detailed Security Analysis\n\n"
    
    # Core security features
    details += f"**Digital Signatures:** {results.get('signatures', 'Not analyzed')}\n\n"
    details += f"**Encryption Status:** {results.get('encryption', 'Not analyzed')}\n\n"
    
    incremental_updates = results.get('incremental_updates', 'Not analyzed')
    if isinstance(incremental_updates, int):
        details += f"**Document Modifications:** {incremental_updates} updates detected\n\n"
    else:
        details += f"**Document Modifications:** {incremental_updates}\n\n"
        
    details += f"**Images Found:** {results.get('image_count', 0)}\n\n"
    details += f"**Internal Objects:** {results.get('xref_total', 'Unknown')}\n\n"

    # File integrity
    file_hash = results.get('file_hash_sha256')
    if file_hash:
        details += f"**File Hash (SHA-256):** `{file_hash[:32]}...`\n\n"
    
    # Embedded content analysis
    if results.get('embedded_files'):
        details += "### Embedded Files Found\n"
        for file_info in results['embedded_files']:
            details += f"- **{file_info['name']}** ({file_info['size']} bytes)\n"
        details += "\n"
    
    if results.get('javascript_payloads'):
        details += f"### Executable Code Analysis\n"
        details += f"Found {len(results['javascript_payloads'])} JavaScript payload(s)\n\n"
        for i, payload in enumerate(results['javascript_payloads'], 1):
            preview = payload[:50] + "..." if len(payload) > 50 else payload
            details += f"- **Script {i}:** {len(payload)} characters\n"
    
    # File optimization analysis
    optimization = results.get('optimization_reduction', 0)
    if isinstance(optimization, (int, float)):
        details += f"### File Structure Analysis\n"
        details += f"**Optimization Potential:** {optimization:.1f}%\n"
        if optimization > 10:
            details += "*High redundancy detected - may indicate tampering*\n"
        elif optimization < -10:
            details += "*Unusual structure detected*\n"
        else:
            details += "*Normal file structure*\n"
    
    # Analysis errors
    analysis_errors = results.get('analysis_errors', [])
    if analysis_errors:
        details += f"\n### Analysis Issues\n"
        details += f"Some analysis components encountered errors:\n"
        for error in analysis_errors[:3]:  # Show top 3 errors
            details += f"- {error}\n"
    
    return details

def create_final_verdict(results):
    """Create user-friendly final verdict"""
    verdict_data = results.get('final_verdict', {})
    
    if not verdict_data:
        return "## Final Verdict\n\nAnalysis incomplete - unable to generate verdict."
    
    verdict = f"""## Final Security Verdict

### {verdict_data['overall']}

{verdict_data['explanation']}

### Security Checklist Results:
"""
    
    for check in verdict_data['detailed_checks']:
        verdict += f"{check}\n"
    
    verdict += f"""

### Summary:
- **Critical Issues:** {verdict_data['red_flag_count']}
- **Failed Security Checks:** {verdict_data['failed_checks']} out of 8
"""

    # Add analysis errors note if any
    analysis_errors = len(results.get('analysis_errors', []))
    if analysis_errors > 0:
        verdict += f"- **Analysis Errors:** {analysis_errors} component(s) failed\n"

    verdict += f"""

### What This Means:
"""
    
    if verdict_data['red_flag_count'] >= 3:
        verdict += "This document shows multiple signs of tampering or malicious content. Do not open it with standard software."
    elif verdict_data['red_flag_count'] >= 1:
        verdict += "This document has some concerning characteristics. Verify its source and use caution."
    else:
        verdict += "This document appears legitimate and safe to use with normal security precautions."
    
    return verdict

# Create Enhanced Gradio Interface (unchanged from your original code)
def create_gradio_interface():
    with gr.Blocks(
        title="TrustPDF - Enhanced Security Scanner",
        theme=gr.themes.Soft(),
        css="""
        .gradio-container {
            max-width: 1400px !important;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
        }
        .verdict-box {
            background: linear-gradient(135deg, #66bb6a 0%, #388e3c 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 10px 0;
        }
        .risk-critical {
            background-color: #ffebee !important;
            border-left: 5px solid #d32f2f !important;
            padding: 15px !important;
        }
        .risk-high {
            background-color: #ffebee !important;
            border-left: 5px solid #f44336 !important;
            padding: 15px !important;
        }
        .risk-medium {
            background-color: #fff3e0 !important;
            border-left: 5px solid #ff9800 !important;
            padding: 15px !important;
        }
        .risk-low {
            background-color: #e8f5e8 !important;
            border-left: 5px solid #4caf50 !important;
            padding: 15px !important;
        }
        """
    ) as interface:
        
        # Header
        gr.HTML("""
        <div class="header">
            <h1>TrustPDF - Enhanced Security Scanner</h1>
            <p><em>Robust PDF analysis with comprehensive error handling</em></p>
        </div>
        """)
        
        with gr.Row():
            with gr.Column(scale=1):
                # File upload section
                gr.Markdown("## Upload PDF File")
                file_input = gr.File(
                    label="Select PDF File for Analysis",
                    file_types=[".pdf"],
                    type="filepath"
                )
                
                analyze_btn = gr.Button(
                    "🔍 Analyze PDF Security",
                    variant="primary",
                    size="lg"
                )
                
                gr.Markdown("""
                ### What We Check:
                - Complete document metadata
                - Creation vs modification dates
                - Software whitelist verification
                - Incremental updates (modifications)
                - Embedded files and scripts
                - Encryption and digital signatures
                - File structure integrity
                - Error-resistant analysis
                """)
            
            with gr.Column(scale=2):
                # Results section
                gr.Markdown("## Analysis Results")
                
                with gr.Tabs():
                    with gr.TabItem("Summary"):
                        summary_output = gr.Markdown(
                            label="Security Assessment Summary",
                            value="Upload a PDF file and click 'Analyze PDF Security' to see results here."
                        )
                    
                    with gr.TabItem("Final Verdict"):
                        verdict_output = gr.Markdown(
                            label="Final Security Verdict",
                            value="The final security verdict will appear here after analysis.",
                            elem_classes=["verdict-box"]
                        )
                    
                    with gr.TabItem("Document Info"):
                        metadata_output = gr.Markdown(
                            label="Complete Document Information",
                            value="Document metadata and software analysis will appear here after analysis."
                        )
                    
                    with gr.TabItem("Security Details"):
                        security_output = gr.Markdown(
                            label="Detailed Security Analysis",
                            value="Detailed security information will appear here after analysis."
                        )
                    
                    with gr.TabItem("Full Log"):
                        console_output = gr.Textbox(
                            label="Complete Analysis Log",
                            placeholder="Complete analysis log will appear here...",
                            lines=25,
                            max_lines=35,
                            show_copy_button=True
                        )
        
        # Event handlers
        def analyze_and_update_all(file_path):
            if not file_path:
                return "No file uploaded", "No verdict available", "No metadata available", "No security details", "No console output"
            
            # Perform analysis
            summary, metadata, security, console, verdict = analyze_pdf_gradio(file_path)
            return summary, verdict, metadata, security, console
        
        # Connect event handlers
        analyze_btn.click(
            fn=analyze_and_update_all,
            inputs=[file_input],
            outputs=[
                summary_output,
                verdict_output,
                metadata_output,
                security_output,
                console_output
            ]
        )
        
        # Add footer with information
        gr.HTML("""
        <div style="text-align: center; margin-top: 30px; padding: 20px; background-color: #f5f5f5; border-radius: 10px;">
            <h3>Robust Security Analysis</h3>
            <p>This version includes comprehensive error handling to analyze even corrupted or malformed PDF files safely.
            All PDF operations are protected with try-catch blocks and null checks.</p>
            <p><strong>Enhanced Features:</strong> Graceful error recovery, detailed error reporting, 
            safe object handling, and improved stability for edge cases.</p>
        </div>
        """)
        
    return interface

# Main execution
if __name__ == "__main__":
    print("🚀 Starting Robust PDF Tampering Detection Tool")
    
    # Create and launch interface
    interface = create_gradio_interface()
    
    # Launch with custom settings
    interface.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        debug=True,
        show_error=True,
        quiet=False
    )