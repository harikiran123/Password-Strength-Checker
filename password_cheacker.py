import math
import re

def calculate_entropy(password):
    """Calculates the entropy of a password based on character variety and length."""
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password):
        charset_size += 32  # Approximate number of special characters

    if charset_size == 0:
        return 0  # No valid characters found

    entropy = len(password) * math.log2(charset_size)
    return entropy

def check_complexity(password):
    """Checks if the password meets length and complexity requirements."""
    length_ok = len(password) >= 8
    lower_ok = any(c.islower() for c in password)
    upper_ok = any(c.isupper() for c in password)
    digit_ok = any(c.isdigit() for c in password)
    special_ok = any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for c in password)

    complexity = [length_ok, lower_ok, upper_ok, digit_ok, special_ok]
    score = sum(complexity)

    if score == 5:
        return "Very Strong"
    elif score == 4:
        return "Strong"
    elif score == 3:
        return "Medium"
    elif score == 2:
        return "Weak"
    else:
        return "Very Weak"

def validate_regex(password):
    """Validates password using regex patterns."""
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return bool(re.match(pattern, password))

def check_password_strength(password):
    """Main function to check password strength."""
    entropy = calculate_entropy(password)
    complexity = check_complexity(password)
    regex_valid = validate_regex(password)

    print(f"Password: {password}")
    print(f"Entropy: {entropy:.2f} bits")
    print(f"Complexity: {complexity}")
    print(f"Regex Validation: {'Pass' if regex_valid else 'Fail'}")

# Example usage
password = input("Enter a password: ")
check_password_strength(password)
