# Desined By @CyberArtist Gaurav Pandey 
#!/usr/bin/env python3

import urllib.parse
import sys
import time
import random
import argparse
import requests
import socket
import re
import json
import whois
from collections import namedtuple
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import tempfile
import os

# Define colors for terminal output (Parrot OS style)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[35m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'

# URL components structure
URLComponents = namedtuple('URLComponents', [
    'scheme', 'netloc', 'path', 'params', 'query', 'fragment', 'domain', 'tld'
])

# Known URL shortening services
SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 'adf.ly', 
    'bit.do', 'shorte.st', 'bc.vc', 'cli.gs', 'ity.im', 'soo.gd', 's2r.co',
    'v.gd', 'prettylinkpro.com', 'viralurl.com', 'qr.net', '1url.com',
    '7.ly', 'adcraft.co', 'adflav.com', 'adfoc.us', 'aka.gr', 'short.to',
    'moourl.com', 'snipurl.com', 'short.ie', 'kl.am', 'wp.me', 'u.to',
    'j.mp', 'fb.me', 'twitthis.com', 'su.pr', 'digg.com', 'url4.eu',
    'sk.gy', 'is.gd', 'dwarfurl.com', 'ff.im', 'tiny.cc', 'urlzen.com',
    'miln.it', 'x.co', 'zz.gd', 'vzturl.com', 'pd.am', 'urls.im', 'cutt.ly',
    'shrunken.com', 'shorturl.at', 'clicky.me', 'bl.ink', 'cutt.us', 'short.cm'
}

# Suspicious patterns
SUSPICIOUS_PATTERNS = [
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address in URL
    r'@',  # @ symbol in URL (often used in phishing)
    r'-\w+\.',  # Hyphenated subdomains
    r'\.(exe|zip|rar|js|vb|bat|cmd|msi)$',  # Direct file downloads
]

def glitchy_banner():
    """Display a glitchy madURL banner"""
    banner = [
        "███╗   ███╗ █████╗ ██████╗ ██╗   ██╗██████╗ ██╗     ",
        "████╗ ████║██╔══██╗██╔══██╗██║   ██║██╔══██╗██║     ",
        "██╔████╔██║███████║██║  ██║██║   ██║██████╔╝██║     ",
        "██║╚██╔╝██║██╔══██║██║  ██║██║   ██║██╔══██╗██║     ",
        "██║ ╚═╝ ██║██║  ██║██████╔╝╚██████╔╝██║  ██║███████╗",
        "╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝"
    ]
    
    # Display banner with glitch effect
    for line in banner:
        glitch_line = ""
        for char in line:
            if random.random() < 0.1:  # 10% chance of glitch
                glitch_char = random.choice(['█', '▓', '▒', '░', '╬', '╩', '╦', '╣', '╠', '╗', '╝', '║', '═'])
                glitch_line += Colors.RED + glitch_char + Colors.END
            else:
                glitch_line += Colors.CYAN + char + Colors.END
        print(glitch_line)
        time.sleep(0.1)
    
    print(f"\n{Colors.YELLOW}🔍 Advanced URL Analysis Tool {Colors.END}")
    print(f"{Colors.CYAN}  [@Spydobyte Toolkit ]{Colors.END}\n")

def decode_animation(text, delay=0.05):
    """Animated decoding effect for text"""
    decoded = ""
    for i, char in enumerate(text):
        # Random characters during decoding
        for _ in range(3):
            random_char = chr(random.randint(33, 126))
            sys.stdout.write(f"\r{Colors.YELLOW}{decoded}{random_char}{Colors.END}")
            sys.stdout.flush()
            time.sleep(delay/3)
        decoded += char
        sys.stdout.write(f"\r{Colors.GREEN}{decoded}{Colors.END}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def expand_url(url):
    """Expand shortened URL by following redirects"""
    try:
        session = requests.Session()
        response = session.head(url, allow_redirects=True, timeout=5)
        return response.url
    except requests.RequestException as e:
        print(f"{Colors.RED}Error expanding URL: {e}{Colors.END}")
        return url

def is_shortened(url):
    """Check if URL is from a known shortening service"""
    netloc = urllib.parse.urlparse(url).netloc
    return any(shortener in netloc for shortener in SHORTENERS)

def analyze_suspicious_patterns(url):
    """Check URL for suspicious patterns"""
    warnings = []
    
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            warnings.append(f"Contains suspicious pattern: {pattern}")
    
    # Check for URL encoding tricks
    if '%' in url and len(re.findall(r'%[0-9a-fA-F]{2}', url)) > 3:
        warnings.append("Uses excessive URL encoding")
    
    return warnings

def get_domain_info(netloc):
    """Extract domain and TLD from netloc"""
    parts = netloc.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        domain = parts[-2] + '.' + tld
        return domain, tld
    return netloc, ""

def analyze_url(url):
    """Parse and analyze the URL components"""
    try:
        parsed = urllib.parse.urlparse(url)
        domain, tld = get_domain_info(parsed.netloc)
        
        components = URLComponents(
            scheme=parsed.scheme,
            netloc=parsed.netloc,
            path=parsed.path,
            params=parsed.params,
            query=parsed.query,
            fragment=parsed.fragment,
            domain=domain,
            tld=tld
        )
        return components
    except Exception as e:
        print(f"{Colors.RED}Error parsing URL: {e}{Colors.END}")
        return None

def get_whois_info(domain):
    """Get WHOIS information for a domain"""
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        print(f"{Colors.RED}Error getting WHOIS info: {e}{Colors.END}")
        return None

def check_virustotal(url, api_key):
    """Check URL against VirusTotal database"""
    if not api_key:
        print(f"{Colors.YELLOW}VirusTotal API key not provided{Colors.END}")
        return None
    
    try:
        # Check if URL is already in VT database
        params = {'apikey': api_key, 'resource': url}
        headers = {"Accept-Encoding": "gzip, deflate"}
        
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report',
                              params=params, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            if result['response_code'] == 1:
                return result
            else:
                # If URL not in database, submit it for scanning
                print(f"{Colors.YELLOW}URL not in VirusTotal database. Submitting for analysis...{Colors.END}")
                params = {'apikey': api_key, 'url': url}
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan',
                                       data=params, headers=headers)
                
                if response.status_code == 200:
                    result = response.json()
                    return result
                else:
                    print(f"{Colors.RED}Error submitting to VirusTotal: {response.status_code}{Colors.END}")
                    return None
        else:
            print(f"{Colors.RED}VirusTotal API error: {response.status_code}{Colors.END}")
            return None
    except Exception as e:
        print(f"{Colors.RED}VirusTotal check failed: {e}{Colors.END}")
        return None

def generate_pdf_report(analysis_data, filename=None):
    """Generate a PDF report of the URL analysis"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"madURL_report_{timestamp}.pdf"
    
    try:
        # Create PDF document
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=30,
            alignment=1  # Center
        )
        title = Paragraph("MadURL Analysis Report", title_style)
        story.append(title)
        
        # Analysis date
        date_style = ParagraphStyle(
            'CustomDate',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=30,
            alignment=1
        )
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        date = Paragraph(f"Analysis performed on: {date_str}", date_style)
        story.append(date)
        
        # URL analyzed
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"URL: {analysis_data['url']}", styles['Heading2']))
        
        if analysis_data.get('expanded_url') and analysis_data['expanded_url'] != analysis_data['url']:
            story.append(Paragraph(f"Expanded URL: {analysis_data['expanded_url']}", styles['Normal']))
        
        # URL Components
        story.append(Spacer(1, 12))
        story.append(Paragraph("URL Components", styles['Heading2']))
        
        comp_data = [
            ['Component', 'Value'],
            ['Scheme', analysis_data['components'].scheme or 'None'],
            ['Network Location', analysis_data['components'].netloc or 'None'],
            ['Domain', analysis_data['components'].domain or 'None'],
            ['TLD', analysis_data['components'].tld or 'None'],
            ['Path', analysis_data['components'].path or 'None'],
            ['Parameters', analysis_data['components'].params or 'None'],
            ['Fragment', analysis_data['components'].fragment or 'None']
        ]
        
        comp_table = Table(comp_data, colWidths=[2*inch, 4*inch])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(comp_table)
        
        # Security Analysis
        story.append(Spacer(1, 12))
        story.append(Paragraph("Security Analysis", styles['Heading2']))
        
        sec_data = [
            ['Check', 'Result', 'Status'],
            ['HTTPS', 'Yes' if analysis_data['components'].scheme == 'https' else 'No', 
             'Secure' if analysis_data['components'].scheme == 'https' else 'Insecure'],
            ['Shortened URL', 'Yes' if analysis_data['is_shortened'] else 'No', 
             'Warning' if analysis_data['is_shortened'] else 'OK'],
            ['Suspicious Patterns', f"{len(analysis_data['warnings'])} found", 
             'Warning' if analysis_data['warnings'] else 'OK']
        ]
        
        sec_table = Table(sec_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        sec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(sec_table)
        
        # Warnings
        if analysis_data['warnings']:
            story.append(Spacer(1, 12))
            story.append(Paragraph("Security Warnings", styles['Heading3']))
            for warning in analysis_data['warnings']:
                story.append(Paragraph(f"• {warning}", styles['Normal']))
        
        # VirusTotal Results
        if analysis_data.get('virustotal'):
            story.append(Spacer(1, 12))
            story.append(Paragraph("VirusTotal Analysis", styles['Heading2']))
            
            vt = analysis_data['virustotal']
            if vt.get('response_code') == 1:
                positives = vt.get('positives', 0)
                total = vt.get('total', 0)
                
                vt_data = [
                    ['Scan Date', vt.get('scan_date', 'N/A')],
                    ['Positives', f"{positives}/{total}"],
                    ['Permalink', vt.get('permalink', 'N/A')]
                ]
                
                vt_table = Table(vt_data, colWidths=[2*inch, 4*inch])
                vt_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(vt_table)
                
                if positives > 0:
                    story.append(Spacer(1, 12))
                    story.append(Paragraph(f"⚠️  Warning: {positives} security vendors flagged this URL as malicious", 
                                          styles['Heading3']))
            else:
                story.append(Paragraph("URL submitted for analysis. Results pending.", styles['Normal']))
        
        # WHOIS Information
        if analysis_data.get('whois_info'):
            story.append(Spacer(1, 12))
            story.append(Paragraph("WHOIS Information", styles['Heading2']))
            
            whois_info = analysis_data['whois_info']
            whois_data = [
                ['Domain', whois_info.domain_name],
                ['Registrar', whois_info.registrar or 'N/A'],
                ['Creation Date', whois_info.creation_date or 'N/A'],
                ['Expiration Date', whois_info.expiration_date or 'N/A'],
                ['Name Servers', ', '.join(whois_info.name_servers) if whois_info.name_servers else 'N/A']
            ]
            
            whois_table = Table(whois_data, colWidths=[2*inch, 4*inch])
            whois_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(whois_table)
        
        # Build PDF
        doc.build(story)
        print(f"{Colors.GREEN}PDF report generated: {filename}{Colors.END}")
        return filename
        
    except Exception as e:
        print(f"{Colors.RED}Error generating PDF report: {e}{Colors.END}")
        return None

def print_tree(components, url, warnings, expanded_url=None):
    """Display URL components in a tree structure"""
    print(f"\n{Colors.BOLD}URL Analysis Tree:{Colors.END}")
    print(f"{Colors.BLUE}┌── {Colors.UNDERLINE}Full URL{Colors.END}{Colors.BLUE}")
    print(f"│   └── {Colors.CYAN}{url}{Colors.END}")
    
    if expanded_url and expanded_url != url:
        print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Expanded URL{Colors.END}{Colors.BLUE}")
        print(f"│   └── {Colors.GREEN}{expanded_url}{Colors.END}")
    
    print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Scheme{Colors.END}{Colors.BLUE}")
    print(f"│   └── {Colors.GREEN}{components.scheme if components.scheme else 'None'}{Colors.END}")
    
    print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Network Location{Colors.END}{Colors.BLUE}")
    print(f"│   └── {Colors.GREEN}{components.netloc if components.netloc else 'None'}{Colors.END}")
    
    print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Domain{Colors.END}{Colors.BLUE}")
    print(f"│   └── {Colors.GREEN}{components.domain}{Colors.END}")
    
    print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Top Level Domain{Colors.END}{Colors.BLUE}")
    print(f"│   └── {Colors.GREEN}{components.tld}{Colors.END}")
    
    print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Path{Colors.END}{Colors.BLUE}")
    print(f"│   └── {Colors.GREEN}{components.path if components.path else 'None'}{Colors.END}")
    
    if components.params:
        print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Parameters{Colors.END}{Colors.BLUE}")
        print(f"│   └── {Colors.GREEN}{components.params}{Colors.END}")
    
    if components.query:
        print(f"{Colors.BLUE}├── {Colors.UNDERLINE}Query String{Colors.END}{Colors.BLUE}")
        queries = urllib.parse.parse_qs(components.query)
        for i, (key, values) in enumerate(queries.items()):
            prefix = "└──" if i == len(queries)-1 else "├──"
            print(f"│   {prefix} {Colors.YELLOW}{key}{Colors.END}: {Colors.GREEN}{', '.join(values)}{Colors.END}")
    
    if components.fragment:
        print(f"{Colors.BLUE}└── {Colors.UNDERLINE}Fragment{Colors.END}{Colors.BLUE}")
        print(f"    └── {Colors.GREEN}{components.fragment}{Colors.END}")
    else:
        print(f"{Colors.BLUE}└── {Colors.UNDERLINE}Fragment{Colors.END}{Colors.BLUE}")
        print(f"    └── {Colors.RED}None{Colors.END}")
    
    # Print security warnings if any
    if warnings:
        print(f"\n{Colors.RED}{Colors.BOLD}⚠️  SECURITY WARNINGS:{Colors.END}")
        for i, warning in enumerate(warnings):
            print(f"{Colors.RED}├── {warning}{Colors.END}")

def print_security_analysis(url, components, expanded_url, virustotal_result=None, whois_info=None):
    """Print security analysis of the URL"""
    print(f"\n{Colors.PURPLE}{Colors.BOLD}🛡️  SECURITY ANALYSIS:{Colors.END}")
    
    # Check if URL is shortened
    if is_shortened(url):
        print(f"{Colors.YELLOW}├── URL is shortened{Colors.END}")
        if expanded_url != url:
            print(f"{Colors.YELLOW}├── Redirects to: {expanded_url}{Colors.END}")
    
    # Check for suspicious patterns
    warnings = analyze_suspicious_patterns(url)
    if warnings:
        for warning in warnings:
            print(f"{Colors.RED}├── {warning}{Colors.END}")
    else:
        print(f"{Colors.GREEN}├── No obvious suspicious patterns detected{Colors.END}")
    
    # Check if using HTTPS
    if components.scheme == 'https':
        print(f"{Colors.GREEN}├── Uses secure HTTPS protocol{Colors.END}")
    else:
        print(f"{Colors.RED}├── Uses insecure HTTP protocol{Colors.END}")
    
    # Check for IP address in URL
    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', components.netloc)
    if ip_match:
        print(f"{Colors.RED}├── Uses IP address instead of domain name: {ip_match.group(0)}{Colors.END}")
    
    # VirusTotal results
    if virustotal_result:
        print(f"{Colors.BLUE}├── {Colors.UNDERLINE}VirusTotal Analysis{Colors.END}{Colors.BLUE}")
        if virustotal_result.get('response_code') == 1:
            positives = virustotal_result.get('positives', 0)
            total = virustotal_result.get('total', 0)
            print(f"│   ├── Scan Date: {virustotal_result.get('scan_date', 'N/A')}")
            print(f"│   ├── Detection: {positives}/{total}")
            if positives > 0:
                print(f"│   └── {Colors.RED}⚠️  {positives} security vendors flagged this URL as malicious{Colors.END}")
            else:
                print(f"│   └── {Colors.GREEN}No security vendors flagged this URL as malicious{Colors.END}")
        else:
            print(f"│   └── {Colors.YELLOW}URL submitted for analysis. Results pending.{Colors.END}")
    
    # WHOIS information
    if whois_info:
        print(f"{Colors.BLUE}├── {Colors.UNDERLINE}WHOIS Information{Colors.END}{Colors.BLUE}")
        print(f"│   ├── Registrar: {whois_info.registrar or 'N/A'}")
        print(f"│   ├── Creation Date: {whois_info.creation_date or 'N/A'}")
        print(f"│   └── Expiration Date: {whois_info.expiration_date or 'N/A'}")

def main():
    parser = argparse.ArgumentParser(description='MadURL - Advanced URL Analysis Tool')
    parser.add_argument('url', help='URL to analyze')
    parser.add_argument('-e', '--expand', action='store_true', help='Expand shortened URLs')
    parser.add_argument('-v', '--virustotal', metavar='API_KEY', help='Check URL with VirusTotal (requires API key)')
    parser.add_argument('-w', '--whois', action='store_true', help='Get WHOIS information for domain')
    parser.add_argument('-p', '--pdf', metavar='FILENAME', nargs='?', const='', 
                       help='Generate PDF report (optional filename)')
    args = parser.parse_args()
    
    # Display glitchy banner
    glitchy_banner()
    
    # Animate URL decoding
    print(f"{Colors.BOLD}Analyzing URL:{Colors.END}", end=" ")
    decode_animation(args.url)
    
    # Check if URL is shortened and expand if requested
    expanded_url = args.url
    if args.expand or is_shortened(args.url):
        print(f"{Colors.YELLOW}Checking for URL shortening...{Colors.END}")
        expanded_url = expand_url(args.url)
    
    # Analyze URL
    components = analyze_url(expanded_url)
    if not components:
        return
    
    # Check for suspicious patterns
    warnings = analyze_suspicious_patterns(expanded_url)
    
    # Get VirusTotal results if requested
    virustotal_result = None
    if args.virustotal:
        print(f"{Colors.YELLOW}Checking VirusTotal...{Colors.END}")
        virustotal_result = check_virustotal(expanded_url, args.virustotal)
    
    # Get WHOIS information if requested
    whois_info = None
    if args.whois:
        print(f"{Colors.YELLOW}Getting WHOIS information...{Colors.END}")
        whois_info = get_whois_info(components.domain)
    
    # Print analysis
    print_tree(components, args.url, warnings, expanded_url if expanded_url != args.url else None)
    print_security_analysis(args.url, components, expanded_url, virustotal_result, whois_info)
    
    # Generate PDF report if requested
    if args.pdf is not None:
        print(f"{Colors.YELLOW}Generating PDF report...{Colors.END}")
        
        # Prepare analysis data for PDF
        analysis_data = {
            'url': args.url,
            'expanded_url': expanded_url,
            'components': components,
            'warnings': warnings,
            'is_shortened': is_shortened(args.url),
            'virustotal': virustotal_result,
            'whois_info': whois_info
        }
        
        filename = args.pdf if args.pdf != '' else None
        generate_pdf_report(analysis_data, filename)
    
    # Print terminal identifier
    print(f"\n{Colors.YELLOW}────────────────────────────────────────────{Colors.END}")
    print(f"{Colors.RED} ID: {Colors.BOLD}@SpydoByte{Colors.END}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python madurl.py <URL> [-e|--expand] [-v API_KEY|--virustotal API_KEY] [-w|--whois] [-p [FILENAME]|--pdf [FILENAME]]{Colors.END}")
        sys.exit(1)
    
    # Check for required dependencies
    try:
        import whois
    except ImportError:
        print(f"{Colors.RED}Error: The 'python-whois' package is required. Install with: pip install python-whois{Colors.END}")
        sys.exit(1)
    
    try:
        from reportlab.lib.pagesizes import letter
    except ImportError:
        print(f"{Colors.RED}Error: The 'reportlab' package is required for PDF generation. Install with: pip install reportlab{Colors.END}")
        sys.exit(1)
    
    main()