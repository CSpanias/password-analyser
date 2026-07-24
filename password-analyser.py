#!/usr/bin/env python3

###############################################################################
# Password Analyser v0.1
#
# Author: Charalampos Spanias (mollysec)
#
# Description:
#
# Analyses recovered Active Directory passwords and generates
# statistics, executive summaries, technical commentary,
# remediation guidance, and XML output.
#
###############################################################################

import argparse
import re
from collections import Counter
from collections import defaultdict

KEYBOARD_PATTERNS = [

    # qwerty row
    "qwe",
    "qwer",
    "qwert",
    "qwerty",
    "qwertyuiop",
    "werty",
    "ertyuiop",
    "trewq",

    # asdf row
    "asd",
    "asdf",
    "asdfg",
    "asdfgh",

    # zxcv row
    "zxc",
    "zxcv",
    "zxcvbn",
    "zxcvbnm",

    # diagonals
    "qaz",
    "qazwsx",
    "wsx",

    # numeric walks
    "q1w2",
    "q1w2e3",

    # azerty
    "azerty",

    # observed variants
    "aqwert",
    "vbnhb",
    "drews",
    "tress",
]

COMMON_PASSWORDS = {
    "password",
    "welcome",
    "letmein",
    "admin",
    "iloveyou",
    "qwerty",
    "starwars",
    "dragon",
    "monkey",
}

DAYS = {
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday"
}

MONTHS = {
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december"
}

SEASONS = {
    "spring",
    "summer",
    "autumn",
    "fall",
    "winter"
}

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def load_passwords(path):

    passwords = []

    with open(path, encoding="utf-8", errors="ignore") as f:

        for line in f:
            line = line.strip()

            if ":" not in line:
                continue

            username, password = line.split(":", 1)
            passwords.append({"username": username, "password": password})

    return passwords


def load_list(path):

    if not path:
        return []

    with open(path, encoding="utf-8", errors="ignore") as f:

        return [
            line.strip()
            for line in f
            if line.strip()
        ]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def mask_password(password):

    if len(password) <= 4:
        return "*" * len(password)

    return (password[:2] + "*" * (len(password) - 4) + password[-2:])


def normalise_text(text):

    substitutions = {
        "@": "a",
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "$": "s",
    }

    text = text.lower()

    for old, new in substitutions.items():
        text = text.replace(old, new)

    return text


def username_base(username):

    user = username.lower()

    if "\\" in user:
        user = user.split("\\")[-1]

    user = user.replace("_adm", "")
    user = user.replace("-adm", "")
    user = user.replace("_da", "")
    user = user.replace("-da", "")

    # Remove trailing digits
    user = re.sub(r"\d+$", "", user)

    return user


def normalise_password(password):

    password = password.lower()

    substitutions = {
        "@": "a",
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "$": "s"
    }

    for old, new in substitutions.items():
        password = password.replace(old, new)

    return password


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def password_lengths(passwords):

    return Counter(len(record["password"]) for record in passwords)


# Most Used Passwords
def top_passwords(passwords, limit=5):

    counts = Counter(record["password"] for record in passwords)
    results = []
    total = len(passwords)

    for password, count in counts.most_common(limit):
        results.append({"password": password, "count": count, "percentage": round(count / total * 100, 1)})

    return results


# Password Reuse
def password_reuse(passwords):

    reuse = []
    counter = Counter(record["password"] for record in passwords)

    for password, count in counter.items():
        if count > 1:
            reuse.append({"password": password, "count": count})

    return reuse


# Recovered Domain Admins
def compromised_admins(passwords, domain_admins):

    admins = []
    admin_set = {user.lower().split("\\")[-1] for user in domain_admins}

    for record in passwords:
        username = (record["username"].lower().split("\\")[-1])

        if username in admin_set:
            admins.append(record)

    return admins


# Non-Compliant Passwords
def load_domain_policy(path):

    policy = {}

    with open(path, encoding="utf-8") as f:

        for line in f:
            if ":" not in line:
                continue

            key, value = (line.split(":", 1))
            policy[key.strip()] = value.strip()

    return policy

def password_length_failures(passwords,minimum_length):

    failures = []

    for record in passwords:
        password = record["password"]

        if len(password) < minimum_length:
            failures.append({"username": record["username"], "password": password, "length": len(password)})

    return failures


# Company-Related Strings
def load_company_words(path):

    if not path:
        return []

    with open(path, encoding="utf-8") as f:

        return [
            line.strip().lower()
            for line in f
            if line.strip()
        ]

def company_name_passwords(passwords, company_words):

    findings = []

    for record in passwords:

        password_normalised = normalise_text(record["password"])
        matches = []

        for word in company_words:
            normalised_word = normalise_text(word)

            if normalised_word in password_normalised:
                matches.append(word)

        if matches:
            findings.append({"username": record["username"], "password": record["password"], "matches": matches})

    return findings


def company_word_stats(company_findings):

    counts = Counter()

    for finding in company_findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()


# Keyboard Walks
def keyboard_walk_passwords(passwords):

    findings = []

    for record in passwords:
        password = record["password"].lower()
        matches = []

        for pattern in KEYBOARD_PATTERNS:

            if pattern in password:
                matches.append(pattern)

        if matches:
            findings.append({"username": record["username"], "password": record["password"], "matches": matches})

    return findings


def keyboard_walk_stats(findings):

    counts = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()


# Usernames in Passwords
def username_variants(username):

    user = username.lower()

    # remove domain
    if "\\" in user:
        user = user.split("\\")[-1]

    variants = {user}

    # john.smith
    if "." in user:

        first, last = user.split(".", 1)

        variants.add(first)
        variants.add(last)
        variants.add(first + last)

        if first:
            variants.add(first[0] + last)

    return {
        variant
        for variant in variants
        if len(variant) >= 3
    }


def username_passwords(passwords):

    findings = []

    for record in passwords:
        password_normalized = normalise_text(record["password"])
        matches = []

        for variant in username_variants(record["username"]):
            if normalise_text(variant) in password_normalized:
                matches.append(variant)

        if matches:
            findings.append({"username": record["username"], "password": record["password"],"matches": matches})

    return findings


# Password Reuse Between Similar Accounts
def reused_passwords(passwords):

    grouped = defaultdict(list)

    for record in passwords:
        grouped[record["password"]].append(record["username"])

    reuse = {}

    for password, users in grouped.items():
        if len(users) > 1:
            reuse[password] = users

    return reuse


def similar_account_reuse(passwords):

    findings = []
    reused = reused_passwords(passwords)

    for password, users in reused.items():
        for i in range(len(users)):
            for j in range(i + 1, len(users)):
                left = users[i]
                right = users[j]

                if (username_base(left) == username_base(right)):
                    findings.append({"password": password, "username": left, "shared_with": right})

    return findings


# Weak/Common Passwords
def common_passwords(passwords):

    findings = []

    for record in passwords:
        password = normalise_password(record["password"])
        matches = []

        for common in COMMON_PASSWORDS:
            if common in password:
                matches.append(common)

        if matches:
            findings.append({"username": record["username"], "password": record["password"], "matches": matches})

    return findings


# Date-Related Strings
def date_passwords(passwords):

    findings = []

    for record in passwords:
        password = record["password"].lower()
        matches = []

        for day in DAYS:
            if day in password:
                matches.append(day)

        for month in MONTHS:
            if month in password:
                matches.append(month)

        for season in SEASONS:
            if season in password:
                matches.append(season)

        if matches:
            findings.append({"username": record["username"], "password": record["password"], "matches": matches})

    return findings

def date_stats(findings):

    counts = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()


# Commonly Used Passwords
def password_frequency(passwords):

    counts = Counter(record["password"] for record in passwords)

    return counts.most_common()

def top_passwords_summary(results, limit=10):

    passwords = (results["password_frequency"]["passwords"])

    return passwords[:limit]


# Character Type Usage
def character_class_adoption(passwords):

    total = len(passwords)

    lower = 0
    upper = 0
    numeric = 0
    special = 0

    for record in passwords:
        password = record["password"]

        if any(c.islower() for c in password):
            lower += 1

        if any(c.isupper() for c in password):
            upper += 1

        if any(c.isdigit() for c in password):
            numeric += 1

        if any(not c.isalnum() for c in password):
            special += 1

    return {
        "lower": round(lower / total * 100, 1),
        "upper": round(upper / total * 100, 1),
        "numeric": round(numeric / total * 100, 1),
        "special": round(special / total * 100, 1),
    }


# Password Length Distribution
def password_length_distribution(passwords):

    lengths = Counter(len(record["password"]) for record in passwords)

    return lengths.most_common()


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def executive_summary(results):

    total = results["total_passwords"]
    admin_count = results["admins"]["count"]
    failure_count = results["password_length"]["count"]
    percentage = results["password_length"]["percentage"]
    minimum_length = results["password_length"]["minimum_length"]
    company_count = results["company_words"]["count"]
    keyboard_count = results["keyboard_walks"]["count"]
    company_text = ""
    username_count = (results["username_passwords"]["count"])
    reuse_count = (results["password_reuse"]["count"])
    common_count = (results["common_passwords"]["count"])
    date_count = (results["date_passwords"]["count"])

    if date_count > 0:

        date_text = (
            f"\n\n{date_count} recovered passwords "
            f"were found to contain variations of "
            f"days, months, seasons, or dates."
        )

    else:
        date_text = ""

    if reuse_count > 0:

        reuse_text = (
            f"\n\n{reuse_count} accounts were identified "
            f"as sharing passwords with similarly named "
            f"user accounts."
        )

    else:
        reuse_text = ""

    if username_count > 0:

        username_text = (
            f"\n\n{username_count} recovered passwords "
            f"were identified as containing the username "
            f"or a variation thereof."
        )

    else:
        username_text = ""

    if company_count > 0:

        company_text = (
            f"\n\nThe organisation name, or a variation thereof, "
            f"was identified within {company_count} recovered "
            f"passwords. Passwords that contain company-related "
            f"terms are particularly susceptible to targeted "
            f"guessing attacks and should be prioritised for remediation."
        )

    else:
        company_text = ""

    if keyboard_count > 0:

        keyboard_text = (
            f"\n\n{keyboard_count} recovered passwords "
            f"were found to contain common keyboard "
            f"walking patterns."
        )

    else:
        keyboard_text = ""

    if common_count > 0:

        common_text = (
            f"\n\n{common_count} recovered passwords "
            f"were identified as variations of common "
            f"passwords or widely used password phrases."
        )

    else:
        common_text = ""

    return f"""
        A password audit was performed against extracted password hashes.

        A total of {total} username and plaintext password combinations
        were recovered and analysed.

        {admin_count} Domain Administrator accounts were identified within
        the recovered password dataset.

        {failure_count} passwords ({percentage}%)
        did not meet the minimum password length requirement
        of {minimum_length} characters.
        {company_text}
        {keyboard_text}
        {username_text}
        {reuse_text}
        {common_text}
        {date_text}
        """.strip()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description="Password Audit")

    parser.add_argument("-M", "--mapped-passwords", required=True, help="mapped-passwords.txt")
    parser.add_argument("-A", "--domain-admins", default="./ntds-organiser/domain-admins.txt", help="domain-admins.txt (default: ./ntds-organiser/domain-admins.txt)")
    parser.add_argument("-P", "--pass-policy", default="./ntds-organiser/domain-policy.txt", help="domain-policy.txt (default: ./ntds-organiser/domain-policy.txt)")
    parser.add_argument("-C", "--company-words", help="File containing company-related words")

    args = parser.parse_args()

    passwords = load_passwords(args.mapped_passwords)
    domain_admins = load_list(args.domain_admins)
    admins = compromised_admins(passwords, domain_admins)
    policy = load_domain_policy(args.pass_policy)
    minimum_length = int(policy["Minimum Password Length"])
    length_failures = password_length_failures(passwords, minimum_length)
    top_passes = top_passwords(passwords)
    company_words = load_company_words(args.company_words)
    company_findings = company_name_passwords(passwords, company_words)
    keyboard_findings = keyboard_walk_passwords(passwords)
    username_findings = username_passwords(passwords)
    reuse_findings = similar_account_reuse(passwords)
    common_password_findings = common_passwords(passwords)
    date_findings = date_passwords(passwords)
    password_frequencies = password_frequency(passwords)
    char_classes = character_class_adoption(passwords)
    length_distribution = (password_length_distribution(passwords))

    results = {}

    results["admins"] = {"accounts": admins,"count": len(admins)}
    results["password_length"] = {"minimum_length": minimum_length, "failures": length_failures, "count": len(length_failures), "percentage": round(len(length_failures) / len(passwords) * 100, 1) if passwords else 0}
    results["top_passwords"] = {"passwords": top_passes, "count": len(top_passes)}
    results["company_words"] = {"count": len(company_findings), "accounts": company_findings, "stats": company_word_stats(company_findings), "company_words": company_words}
    results["keyboard_walks"] = {"count": len(keyboard_findings), "accounts": keyboard_findings, "stats": keyboard_walk_stats(keyboard_findings)}
    results["total_passwords"] = len(passwords)
    results["unique_passwords"] = len(set(p["password"]for p in passwords))
    results["username_passwords"] = {"count": len(username_findings), "accounts": username_findings}
    results["password_reuse"] = {"count": len(reuse_findings), "accounts": reuse_findings}
    results["common_passwords"] = {"count": len(common_password_findings), "accounts": common_password_findings}
    results["date_passwords"] = {"count": len(date_findings), "accounts": date_findings, "stats": date_stats(date_findings)}
    results["password_frequency"] = {"passwords": password_frequencies}
    results["character_classes"] = (char_classes)
    results["password_lengths"] = {"lengths": length_distribution}

    print()
    print(executive_summary(results))
    print()

    print(f"Passwords Analysed : {results['total_passwords']}")
    print(f"Compromised Admins : {results['admins']['count']}")
    print(f"Unique Passwords   : {results['unique_passwords']}")
    print(f"Company-related Words : {results['company_words']['count']}")
    print(f"Keyboard Walks : {results['keyboard_walks']['count']}")
    print(f"Username in Password : {results['username_passwords']['count']}")
    print(f"Password Reuse Between Similar Accounts : {results['password_reuse']['count']}")
    print(f"Common Passwords : {results['common_passwords']['count']}")
    print(f"Date-Related Passwords : {results['date_passwords']['count']}")
    print(f"Non-Compliant Passwords : {results['password_length']['count']}")

    print("\nCompromised Admins:")
    print(f"{results['admins']['accounts']}")

    print("\nCompany-Related Words:")
    print(f"{results['company_words']['accounts']}")

    print("\nUsernames Within Passwords:")
    print(f"{results['username_passwords']['accounts']}")

    print("\nSimilar Accounts Reuse:")
    print(f"{results['password_reuse']['accounts']}")

    print("\nCommon Passwords:")
    print(f"{results['common_passwords']['accounts']}")

    print("\nDate-Related Passwords:")
    print(f"{results['date_passwords']['accounts']}")

    print("\nNon-Compliant Passwords:")
    print(f"{results['password_length']['failures']}")

    print("\nMost Frequent Passwords")
    for password, count in (top_passwords_summary(results)):
        print(f"  {password:<20} {count}")

    print("\nCharacter Class Adoption")
    print(f"Lowercase : {results['character_classes']['lower']}%")
    print(f"Uppercase : {results['character_classes']['upper']}%")
    print(f"Numbers   : {results['character_classes']['numeric']}%")
    print(f"Special   : {results['character_classes']['special']}%")

    print("\nMost Common Password Lengths")
    for length, count in (results["password_lengths"]["lengths"][:10]):
        percentage = round(count / results["total_passwords"] * 100, 1)
        print(f"  {length:<2} {count:<4} ({percentage}%)")


if __name__ == "__main__":
    main()