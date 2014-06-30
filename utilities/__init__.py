# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

ATTACK_PATTERN_MAPPING =  { "Abuse of functionality" : ("CAPEC-210", "Abuse of Functionality"),
                          "Brute force": ("CAPEC-112", "Brute Force"),
                          "Buffer overflow": ("CAPEC-100", "Overflow Buffers"),
                          "Cache poisoning": ("CAPEC-141", "Cache Poisoning"),
                          "Session prediction": ("CAPEC-351", "Credential/Session Prediction"),
                          "CSRF": ("CAPEC-342", "Cross-Site Request Forgery"),
                          "XSS": ("CAPEC-18", "Embedding Scripts in Non-Script Elements"),                            
                          "Cryptanalysis": ("CAPEC-97", "Cryptanalysis"),                        
                          "DoS": ("CAPEC-119", "Deplete Resources"),
                          "Footprinting": ("CAPEC-169", "Footprinting"),                   
                          "Forced browsing": ("CAPEC-87", "Forceful Browsing"),
                          "Format string attack": ("CAPEC-135", "Format String Injection"),
                          "Fuzz testing": ("CAPEC-28", "Fuzzing"),
                          "HTTP request smuggling": ("CAPEC-33", "HTTP Request Smuggling"),
                          "HTTP request splitting": ("CAPEC-105", "HTTP Request Splitting"),
                          "HTTP response smuggling": ("CAPEC-273", "HTTP Response Smuggling"),
                          "HTTP Response Splitting": ("CAPEC-34", "HTTP Response Splitting"),
                          "Integer overflows": ("CAPEC-92", "Forced Integer Overflow"),
                          "LDAP injection": ("CAPEC-136", "LDAP Injection"),
                          "Mail command injection": ("CAPEC-183", "IMAP/SMTP Command Injection"),
                          "MitM": ("CAPEC-94", "Man in the Middle Attack"),
                          "Null byte injection": ("CAPEC-52", "Embedding NULL Bytes"),            
                          "Offline cracking": ("CAPEC-49", "Password Brute Forcing"),                
                          "OS commanding": ("CAPEC-364", "OS Commanding"),
                          "Pass-the-hash": 0,   # yet
                          "Path traversal": ("CAPEC-126", "Path Traversal"),
                          "RFI": ("CAPEC-253", "Remote Code Inclusion"),
                          "Reverse engineering": ("CAPEC-188", "Reverse Engineering"),
                          "Routing detour": ("CAPEC-365", "Routing Detour"),
                          "Session fixation": ("CAPEC-61", "Session Fixation"),
                          "Session replay": ("CAPEC-60", "Reusing Session IDs (aka Session Replay)"),
                          "Soap array abuse": ("CAPEC-279", "Soap Manipulation"),                            
                          "Special element injection": None, # yet
                          "SQLi": ("CAPEC-66", "SQL Injection"),
                          "SSI injection": ("CAPEC-101", "Server Side Include (SSI) Injection"),            
                          "URL redirector abuse": ("CAPEC-371", "URL Redirector Abuse"),
                          "Use of backdoor or C2": ("CAPEC-115", "Authentication Bypass"),
                          "Use of stolen creds": 0, # yet
                          "XML attribute blowup": ("CAPEC-229", "XML Attribute Blowup"),
                          "XML entity expansion": ("CAPEC-197", "XML Entity Expansion"),
                          "XML external entities": ("CAPEC-221", "XML External Entities"),
                          "XML injection": ("CAPEC-250", "XML Injection"),
                          "XPath injection": ("CAPEC-83", "XPath Injection"),
                          "XQuery injection": ("CAPEC-84", "XQuery Injection"),
                          "Virtual machine escape": 0, # yet
                          "Unknown": "Unknown",
                          "Other": "Other"
    }

