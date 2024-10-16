import re
import hashlib
import requests

# Load a list of common passwords
def load_common_passwords():
    common_passwords = set()
    try:
        with open("common_passwords.txt", "r") as file:
            for line in file:
                common_passwords.add(line.strip())
    except FileNotFoundError:
        print("Error: 'common_passwords.txt' not found.")
    return common_passwords

# Check if password has been exposed in a data breach (Using Have I Been Pwned API)
def check_pwned_password(password):
    # Hash the password using SHA-1 (as required by the API)
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, rest = sha1_password[:5], sha1_password[5:]
    
    # Query the API for the first 5 characters of the hash
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)
    
    if response.status_code != 200:
        print("Error: Could not check Have I Been Pwned API")
        return False

    # Check if the hash suffix is in the response
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == rest:
            return int(count)  # Return the number of times this password was found
    return 0

# Password strength checker
def password_strength(password, common_passwords):
    # Initialize a score
    score = 0
    feedback = []
    
    # Check for common passwords
    if password in common_passwords:
        feedback.append("This is a commonly used password. Choose something more unique.")
        return score, "Very Weak Password", feedback

    # Check length
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password should be at least 12 characters long.")
    
    # Check for character variety
    if re.search(r"[A-Z]", password):  # Uppercase letter
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")
        
    if re.search(r"[a-z]", password):  # Lowercase letter
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")
        
    if re.search(r"\d", password):  # Number
        score += 1
    else:
        feedback.append("Add at least one number.")
        
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Special character
        score += 1
    else:
        feedback.append("Add at least one special character.")
    
    # Check for repetition
    if re.search(r"(.)\1{2,}", password):  # Repetition of the same character more than twice
        score -= 1
        feedback.append("Avoid repeating characters too much.")
    
    # Determine password strength based on score
    if score <= 2:
        return score, "Weak Password", feedback
    elif score == 3 or score == 4:
        return score, "Medium Password", feedback
    else:
        return score, "Strong Password", feedback

# Main function
def main():
    # Load the common passwords list
    common_passwords = load_common_passwords()

    # Get user input for the password
    password = input("Enter a password: ")
    
    # Hash the password using SHA-256
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(f"SHA-256 hash of your password: {hashed_password}")
    
    # Check password strength
    score, strength, feedback = password_strength(password, common_passwords)
    print(f"Password strength: {strength}")
    
    # Print feedback for improvement
    if feedback:
        print("Suggestions to improve your password:")
        for suggestion in feedback:
            print(f"- {suggestion}")
    
    # Check if the password has been exposed in a data breach
    pwned_count = check_pwned_password(password)
    if pwned_count > 0:
        print(f"Warning: This password has been seen {pwned_count} times in data breaches!")
    else:
        print("Good news: This password has not been found in known breaches.")

if __name__ == "__main__":
    main()
