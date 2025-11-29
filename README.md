# SQL_Injection_Scanner
A lightweight SQL Injection Scanner built to identify basic SQL injection vulnerabilities in web applications, aimed at learning and demonstrating core cybersecurity concepts.
# SQL Injection Scanner  

## Overview

This is a simple, error-based **SQL Injection Scanner** built as part of my Cyber Security internship with **Syntecxhub**.

The tool:
- Takes a URL with query parameters
- Injects multiple SQL payloads
- Detects SQL error messages in the response
- Reports potential SQL Injection points
- Generates a full scan summary

> Use only on authorized targets (DVWA, your own lab, or systems you have permission to test).

---

## Features

- Common SQL payload injections  
- Error signature detection  
- Parameter-by-parameter testing  
- Custom report output  
- Clean CLI interface  

---

## Installation

```bash
pip install -r requirements.txt
