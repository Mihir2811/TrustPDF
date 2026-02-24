"""
Enhanced FastAPI Server for PDF Tampering Detection Tool
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, Any, List
from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import your enhanced PDF detector class
from app import PDFTamperingDetector

# Create FastAPI app
app = FastAPI(title="TrustPDF Enhanced", version="2.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")

# Create directories
os.makedirs("static", exist_ok=True)
os.makedirs("uploads", exist_ok=True)

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main HTML interface"""
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Welcome to TrustPDF Enhanced</h1><p>Please ensure static/index.html exists</p>",
            status_code=200
        )

@app.post("/analyze")
async def analyze_pdf(file: UploadFile = File(...)):
    """
    Analyze uploaded PDF file and return enhanced results with Final Verdict
    """
    # Validate file
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")
    
    # Read file content first to get size
    content = await file.read()
    file_size = len(content)
    
    if file_size > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")
    
    # Save uploaded file temporarily
    temp_file_path = None
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        # Run enhanced analysis
        detector = PDFTamperingDetector(temp_file_path)
        results = detector.analyze_pdf()
        
        # Format results for frontend
        formatted_results = format_enhanced_results_for_frontend(results, file.filename, file_size)
        
        return JSONResponse(content=formatted_results)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Clean up temporary file
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass  # Ignore cleanup errors

def format_enhanced_results_for_frontend(results: Dict[Any, Any], filename: str, file_size: int) -> Dict[str, Any]:
    """
    Format enhanced analysis results for the frontend interface
    """
    # Get overall risk level from results
    overall_risk = results.get('overall_risk_level', 'Unknown')
    
    # Get verdict data
    final_verdict = results.get('final_verdict', {})
    failed_checks = final_verdict.get('failed_checks', 0)
    
    # Determine risk class for CSS based on failed checks
    if failed_checks >= 4:
        risk_class = 'risk-critical'
        risk_description = 'Multiple critical security issues detected'
    elif failed_checks >= 2:
        risk_class = 'risk-medium'
        risk_description = 'Some security concerns detected'
    else:
        risk_class = 'risk-low'
        risk_description = 'Document appears relatively safe'
    
    # Format file size
    file_size_mb = round(file_size / (1024 * 1024), 2)
    
    # Extract key metrics
    incremental_updates = results.get('incremental_updates', 0)
    if isinstance(incremental_updates, str):
        incremental_updates = 0
        
    embedded_files_count = len(results.get('embedded_files', []))
    javascript_count = results.get('javascript_count', 0)
    
    # Format comprehensive metadata for table display
    comprehensive_meta = results.get('comprehensive_metadata', {})
    metadata_table = []
    
    # Define the order and labels for metadata display
    metadata_fields = {
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
    
    for field, label in metadata_fields.items():
        value = comprehensive_meta.get(field)
        if value:
            metadata_table.append({
                'key': label,
                'value': str(value)
            })
        else:
            metadata_table.append({
                'key': label,
                'value': 'Not specified'
            })
    
    # Format security issues, tampering indicators, and red flags
    all_findings = []
    
    # Red flags (most serious)
    for flag in results.get('red_flags', []):
        all_findings.append({
            'type': 'critical',
            'title': 'Critical Security Flag',
            'description': flag,
            'icon': 'alert-triangle'
        })
    
    # Security issues (serious)
    for issue in results.get('security_issues', []):
        all_findings.append({
            'type': 'error',
            'title': 'Security Issue',
            'description': issue,
            'icon': 'alert-circle'
        })
    
    # Tampering indicators (moderate)
    for indicator in results.get('tampering_indicators', []):
        all_findings.append({
            'type': 'warning',
            'title': 'Tampering Indicator',
            'description': indicator,
            'icon': 'alert-circle'
        })
    
    # Analysis errors (informational)
    for error in results.get('analysis_errors', []):
        all_findings.append({
            'type': 'info',
            'title': 'Analysis Error',
            'description': error,
            'icon': 'info'
        })
    
    # Format embedded files
    embedded_files = []
    for file_info in results.get('embedded_files', []):
        embedded_files.append({
            'name': file_info['name'],
            'size': file_info['size'],
            'size_formatted': format_bytes(file_info['size'])
        })
    
    # Format JavaScript payloads
    javascript_payloads = []
    for i, payload in enumerate(results.get('javascript_payloads', []), 1):
        javascript_payloads.append({
            'id': i,
            'size': len(payload),
            'preview': payload[:100] + "..." if len(payload) > 100 else payload
        })
    
    # Format console output with enhanced styling
    console_output = results.get('console_output', [])
    console_lines = []
    for line in console_output:
        # Determine log level based on content
        if any(word in line for word in ['🚨', 'RED FLAG', 'CRITICAL']):
            log_level = 'critical'
            color_class = 'text-red-300 font-semibold'
        elif any(word in line for word in ['❌', 'ERROR', 'FAILED']):
            log_level = 'error'
            color_class = 'text-red-400'
        elif any(word in line for word in ['⚠️', 'WARNING', 'SUSPICIOUS']):
            log_level = 'warning'
            color_class = 'text-yellow-400'
        elif any(word in line for word in ['✅', 'SUCCESS', 'SAFE']):
            log_level = 'success'
            color_class = 'text-green-400'
        elif any(word in line for word in ['ℹ️', 'INFO', 'ANALYSIS']):
            log_level = 'info'
            color_class = 'text-blue-400'
        else:
            log_level = 'status'
            color_class = 'text-gray-300'
        
        console_lines.append({
            'level': log_level,
            'message': line,
            'color_class': color_class
        })
    
    # Format Final Verdict
    verdict_formatted = format_final_verdict(final_verdict, overall_risk)
    
    return {
        'file_info': {
            'name': filename,
            'size': file_size,
            'size_formatted': f"{file_size_mb} MB",
            'hash': results.get('file_hash_sha256', 'N/A')
        },
        'risk_assessment': {
            'level': overall_risk,
            'class': risk_class,
            'description': risk_description,
            'failed_checks': failed_checks
        },
        'quick_stats': {
            'incremental_updates': incremental_updates,
            'embedded_files': embedded_files_count,
            'javascript_blocks': javascript_count,
            'failed_security_checks': failed_checks
        },
        'metadata': {
            'table': metadata_table,
            'has_metadata': bool(comprehensive_meta),
            'comprehensive': comprehensive_meta
        },
        'security_details': {
            'encryption': results.get('encryption', 'Not analyzed'),
            'embedded_files': embedded_files,
            'javascript_payloads': javascript_payloads,
            'xref_total': results.get('xref_total', 0),
            'image_count': results.get('image_count', 0),
            'optimization_reduction': results.get('optimization_reduction', 0)
        },
        'findings': all_findings,
        'recommendations': results.get('recommendations', []),
        'console_output': console_lines,
        'final_verdict': verdict_formatted,
        'analysis_complete': True,
        'analysis_errors_count': len(results.get('analysis_errors', []))
    }

def format_final_verdict(verdict_data: Dict[str, Any], overall_risk: str) -> Dict[str, Any]:
    """Format the final verdict for frontend display"""
    if not verdict_data:
        return {
            'overall': 'Analysis Incomplete',
            'explanation': 'Unable to generate final verdict',
            'detailed_checks': [],
            'icon': '🔍',
            'css_class': 'verdict-low',
            'summary': 'No verdict available',
            'failed_checks': 0
        }
    
    # Determine icon and CSS class based on overall risk
    if 'HIGH RISK' in overall_risk:
        icon = '🔴'
        css_class = 'verdict-critical'
    elif 'MEDIUM RISK' in overall_risk:
        icon = '🟡'
        css_class = 'verdict-medium'
    else:
        icon = '🟢'
        css_class = 'verdict-low'
    
    # Format detailed checks for display
    formatted_checks = []
    for check in verdict_data.get('detailed_checks', []):
        if check.startswith('✅'):
            formatted_checks.append({
                'status': 'pass',
                'text': check[2:].strip(),  # Remove emoji
                'icon': '✅'
            })
        elif check.startswith('❌'):
            formatted_checks.append({
                'status': 'fail',
                'text': check[2:].strip(),  # Remove emoji
                'icon': '❌'
            })
        elif check.startswith('⚠️'):
            formatted_checks.append({
                'status': 'warning',
                'text': check[2:].strip(),  # Remove emoji
                'icon': '⚠️'
            })
        else:
            formatted_checks.append({
                'status': 'info',
                'text': check,
                'icon': 'ℹ️'
            })
    
    # Create summary based on failed checks
    failed_checks = verdict_data.get('failed_checks', 0)
    
    if failed_checks >= 4:
        summary = f"Document failed {failed_checks}/8 security checks. High risk of tampering or malicious content."
    elif failed_checks >= 2:
        summary = f"Document failed {failed_checks}/8 security checks. Some security concerns detected."
    else:
        summary = f"Document passed most security checks ({8-failed_checks}/8). Appears trustworthy with normal security precautions."
    
    return {
        'overall': verdict_data.get('overall', 'Unknown'),
        'explanation': verdict_data.get('explanation', 'No explanation available'),
        'detailed_checks': formatted_checks,
        'icon': icon,
        'css_class': css_class,
        'summary': summary,
        'failed_checks': failed_checks,
        'total_checks': 8,
        'raw_checks': verdict_data.get('detailed_checks', [])
    }

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format"""
    if bytes_value < 1024:
        return f"{bytes_value} B"
    elif bytes_value < 1024 * 1024:
        return f"{bytes_value / 1024:.1f} KB"
    else:
        return f"{bytes_value / (1024 * 1024):.1f} MB"

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "TrustPDF Enhanced Security Scanner",
        "version": "2.0.0",
        "features": [
            "Comprehensive metadata validation",
            "Software whitelist verification", 
            "Enhanced tampering detection",
            "User-friendly security verdicts",
            "8-point security checklist"
        ]
    }

@app.get("/api/info")
async def get_api_info():
    """API information endpoint"""
    return {
        "name": "TrustPDF Enhanced API",
        "version": "2.0.0",
        "description": "Advanced PDF security analysis with comprehensive tampering detection",
        "endpoints": {
            "/": "Main web interface",
            "/analyze": "POST - Upload and analyze PDF file",
            "/health": "GET - Health check",
            "/api/info": "GET - API information"
        },
        "security_checks": [
            "1. Complete metadata validation (format, title, author, creator, producer, dates)",
            "2. Creation vs modification date consistency",
            "3. Incremental update detection (document modifications)",
            "4. Software whitelist verification with 85% similarity threshold",
            "5. JavaScript and executable code detection",
            "6. Encryption analysis",
            "7. Embedded files detection",
            "8. File structure integrity (orphaned objects within ±10%)"
        ],
        "risk_levels": {
            "LOW": "0-1 failed checks",
            "MEDIUM": "2-3 failed checks", 
            "HIGH": "4+ failed checks"
        }
    }

@app.post("/api/quick-check")
async def quick_check(file: UploadFile = File(...)):
    """
    Quick security check endpoint - returns only risk level and critical issues
    """
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")
    
    content = await file.read()
    file_size = len(content)
    
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")
    
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        detector = PDFTamperingDetector(temp_file_path)
        results = detector.analyze_pdf()
        
        final_verdict = results.get('final_verdict', {})
        
        return {
            'filename': file.filename,
            'risk_level': results.get('overall_risk_level', 'Unknown'),
            'failed_checks': final_verdict.get('failed_checks', 0),
            'total_checks': 8,
            'verdict': final_verdict.get('overall', 'Unknown'),
            'critical_issues': results.get('red_flags', [])[:3],  # Top 3 critical issues
            'is_safe': final_verdict.get('failed_checks', 0) < 2
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Quick check failed: {str(e)}")
    
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
            except Exception:
                pass

@app.get("/api/quick-check")
async def quick_check_info():
    """
    Quick check endpoint info - GET method
    """
    return {
        "endpoint": "/api/quick-check",
        "method": "POST",
        "description": "Quick security check - returns only risk level and critical issues",
        "usage": "Send a POST request with a PDF file in the 'file' field",
        "example": "curl -X POST http://localhost:8000/api/quick-check -F 'file=@document.pdf'"
    }

if __name__ == "__main__":
    print("Starting TrustPDF Enhanced PDF Security Scanner")
    print("="*30)
    print("Server will be available at: http://localhost:8000")
    print("-"*30)
    print("Web interface at: http://localhost:8000/")
    print("-"*30)
    print("API docs at: http://localhost:8000/docs")
    print("-"*30)
    print("Health check at: http://localhost:8000/health")
    print("-"*30)
    print("⚡ Quick check at: POST http://localhost:8000/api/quick-check")
    print("="*30)
    print("Press CTRL+C to stop the server")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )