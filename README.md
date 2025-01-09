# Password Strength Checker

## Overview
The **Password Strength Checker** is a Python application designed to help users assess the strength of their passwords. It evaluates passwords based on various criteria, provides feedback for improvement, and checks if the password has been exposed in data breaches using the **Have I Been Pwned** API. 

## Features
- **Strength Evaluation**: This checker checks password length, character variety (uppercase, lowercase, numbers, special characters), and repetition.
- **Common Password Check**: Compares the entered password against a list of commonly used passwords.
- **Breach Check**: Queries the Have I Been Pwned API to see if the password has been compromised in known data breaches.
- **SHA-256 Hashing**: Hashes the password using SHA-256 for added security.

## Requirements
- Python 3.x
- `requests` library


