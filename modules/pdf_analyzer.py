import re

PDF_SUSPICIOUS_ELEMENTS = {
    rb'/JS': "Embedded JavaScript",
    rb'/JavaScript': "Embedded JavaScript",
    rb'/OpenAction': "Automatic Action on Open (Auto-Run)",
    rb'/Launch': "External Command / File Execution (Launch)",
    rb'/EmbeddedFiles': "Embedded Files (Dropper / Payload Container)",
    rb'/URI': "External URI Links (Potential Phishing / C2)"
}

def analyze_pdf_content(data):
    """
    Performs static triage on PDFs looking for interactive or malicious elements.
    Returns a list of strings describing the found tactics.
    """
    findings = []
    for pattern, desc in PDF_SUSPICIOUS_ELEMENTS.items():
        if re.search(pattern, data, re.IGNORECASE):
            findings.append(desc)
    return findings
