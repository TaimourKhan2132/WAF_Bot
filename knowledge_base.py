"""
knowledge_base.py
Knowledge Base for WAF Rule Recommender.
Contains 22 specific attack signatures for SQLi, XSS, Command Injection, and CSRF.
"""

waf_rules = [
    #  SQL INJECTION (SQLi) 
    {
        "id": 1001, "name": "SQLi - Boolean Based",
        "pattern": r"('|\")\s*OR\s*('|\")?1('|\")?\s*=\s*('|\")?1",
        "description": "Detects classic boolean bypass attempts (e.g., ' OR 1=1).", "risk": "Critical"
    },
    {
        "id": 1002, "name": "SQLi - Union Select",
        "pattern": r"UNION\s+SELECT",
        "description": "Detects attempts to combine results from multiple tables.", "risk": "Critical"
    },
    {
        "id": 1003, "name": "SQLi - Comment Injection",
        "pattern": r"(--|#|\/\*)",
        "description": "Detects SQL comment characters used to truncate queries.", "risk": "High"
    },
    {
        "id": 1004, "name": "SQLi - Stacked Queries",
        "pattern": r";\s*DROP\s+TABLE",
        "description": "Detects stacked queries attempting to delete data.", "risk": "Critical"
    },
    {
        "id": 1005, "name": "SQLi - System Catalog Access",
        "pattern": r"information_schema",
        "description": "Detects attempts to access database metadata.", "risk": "High"
    },

    #  CROSS-SITE SCRIPTING (XSS) 
    {
        "id": 2001, "name": "XSS - Script Tag",
        "pattern": r"<script>",
        "description": "Detects standard HTML script tags.", "risk": "Critical"
    },
    {
        "id": 2002, "name": "XSS - Javascript Protocol",
        "pattern": r"javascript:",
        "description": "Detects javascript URI schemes in attributes.", "risk": "High"
    },
    {
        "id": 2003, "name": "XSS - Event Handlers",
        "pattern": r"(onload|onerror|onmouseover)\s*=",
        "description": "Detects malicious event handlers in HTML tags.", "risk": "Medium"
    },
    {
        "id": 2004, "name": "XSS - Iframe Injection",
        "pattern": r"<iframe",
        "description": "Detects hidden frames often used for phishing or redirection.", "risk": "High"
    },
    {
        "id": 2005, "name": "XSS - SVG Vector",
        "pattern": r"<svg",
        "description": "Detects SVG tags which can embed scripts.", "risk": "Medium"
    },

    #  COMMAND INJECTION 
    {
        "id": 3001, "name": "OS Command Injection - Pipes",
        "pattern": r"(\|\||\|)\s*(ls|cat|nc|netcat|whoami)",
        "description": "Detects chaining commands using pipes.", "risk": "Critical"
    },
    {
        "id": 3002, "name": "OS Command Injection - System Calls",
        "pattern": r"(exec|system|passthru)\(",
        "description": "Detects PHP/Code execution functions.", "risk": "Critical"
    },

    # PATH TRAVERSAL (LFI) 
    {
        "id": 4001, "name": "Path Traversal - Parent Directory",
        "pattern": r"\.\./",
        "description": "Detects attempts to climb up the directory tree.", "risk": "High"
    },
    {
        "id": 4002, "name": "LFI - Critical Files",
        "pattern": r"(/etc/passwd|boot\.ini|win\.ini)",
        "description": "Detects access attempts to known system files.", "risk": "Critical"
    },

    #  CORS (Cross-Origin Resource Sharing) 
    {
        "id": 5001, "name": "CORS - Wildcard Origin",
        "pattern": r"Access-Control-Allow-Origin:\s*\*",
        "description": "Detects overly permissive CORS configurations (Wildcard).", "risk": "Medium"
    },
    {
        "id": 5002, "name": "CORS - Null Origin",
        "pattern": r"Origin:\s*null",
        "description": "Detects requests sending 'null' origin, often used in sandbox exploits.", "risk": "Medium"
    },

    #  CSRF (Cross-Site Request Forgery) 
    {
        "id": 6001, "name": "CSRF - Missing Referer",
        "pattern": r"Referer:\s*$",
        "description": "Detects requests with empty referer headers where expected.", "risk": "Low"
    },
    {
        "id": 6002, "name": "CSRF - Token Bypass Attempt",
        "pattern": r"csrf_token=\s*$",
        "description": "Detects empty CSRF tokens in request bodies.", "risk": "High"
    },

    #  MISC / PROTOCOL ANOMALIES 
    {
        "id": 7001, "name": "Scanner Detection - SQLMap",
        "pattern": r"sqlmap",
        "description": "Detects User-Agent or payloads associated with SQLMap.", "risk": "High"
    },
    {
        "id": 7002, "name": "Scanner Detection - Nikto",
        "pattern": r"Nikto",
        "description": "Detects User-Agent associated with Nikto scanner.", "risk": "Medium"
    },
    {
        "id": 7003, "name": "Method Not Allowed",
        "pattern": r"TRACE",
        "description": "Detects TRACE method often used for Cross-Site Tracing (XST).", "risk": "Low"
    }
]


concepts = {
    # HIGH LEVEL CONCEPTS
    "sql injection": (
        "SQL Injection (SQLi) is a critical vulnerability where an attacker interferes with the queries "
        "an application makes to its database. This can allow attackers to view data they are not normally "
        "able to retrieve, such as passwords or other user data."
    ),
    "xss": (
        "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by "
        "other users. These scripts can hijack user sessions, deface websites, or redirect the user to malicious sites."
    ),
    "csrf": (
        "Cross-Site Request Forgery (CSRF) is an attack that forces an authenticated user to execute unwanted "
        "actions on a web application. The attack relies on the browser automatically sending session cookies."
    ),
    "waf": (
        "A Web Application Firewall (WAF) filters, monitors, and blocks HTTP traffic to and from a web application. "
        "It protects against attacks like SQLi, XSS, and CSRF by adhering to a set of security rules."
    ),
    
    #  SPECIFIC ATTACK TYPES
    "boolean based sqli": (
        "Boolean-based SQL Injection relies on sending an SQL query to the database which forces the application "
        "to return a different result depending on whether the query returns a TRUE or FALSE result."
    ),
    "union based sqli": (
        "Union-based SQL Injection uses the UNION SQL operator to combine the results of two or more SELECT "
        "statements into a single result, allowing the attacker to retrieve data from other tables."
    ),
    "stored xss": (
        "Stored XSS (Persistent XSS) occurs when the malicious script is permanently stored on the target server "
        "(e.g., in a database or forum post) and served to victims when they view the page."
    ),
    "reflected xss": (
        "Reflected XSS occurs when the malicious script is reflected off the web server, such as in an error message "
        "or search result, and is immediately executed by the browser."
    )
}