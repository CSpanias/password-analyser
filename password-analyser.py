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
from collections import Counter

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
# Analysis
# ---------------------------------------------------------------------------

def password_lengths(passwords):

    return Counter(
        len(record["password"])
        for record in passwords
    )


def top_passwords(passwords, limit=5):

    counts = Counter(record["password"] for record in passwords)
    results = []
    total = len(passwords)

    for password, count in counts.most_common(limit):
        results.append({
            "password": password,
            "count": count,
            "percentage": round(count / total * 100, 1)
        })

    return results


def password_reuse(passwords):

    reuse = []

    counter = Counter(
        record["password"]
        for record in passwords
    )

    for password, count in counter.items():
        if count > 1:
            reuse.append({"password": password, "count": count})

    return reuse


def compromised_admins(passwords, domain_admins):

    admins = []
    admin_set = {
        user.lower().split("\\")[-1]
        for user in domain_admins
    }

    for record in passwords:
        username = (record["username"].lower().split("\\")[-1])

        if username in admin_set:
            admins.append(record)

    return admins

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
            failures.append(
                {
                    "username": record["username"],
                    "password": password,
                    "length": len(password)
                }
            )

    return failures

def mask_password(password):

    if len(password) <= 4:
        return "*" * len(password)

    return (
        password[:2]
        + "*" * (len(password) - 4)
        + password[-2:]
    )

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
            findings.append({
                "username": record["username"],
                "password": record["password"],
                "matches": matches
            })

    return findings


def company_word_stats(company_findings):

    counts = Counter()

    for finding in company_findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()

def normalise_text(text):

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

    text = text.lower()

    for old, new in substitutions.items():
        text = text.replace(old, new)

    return text


def keyboard_walk_passwords(passwords):

    findings = []

    for record in passwords:

        password = record["password"].lower()

        matches = []

        for pattern in KEYBOARD_PATTERNS:

            if pattern in password:

                matches.append(pattern)

        if matches:

            findings.append({
                "username": record["username"],
                "password": record["password"],
                "matches": matches
            })

    return findings


def keyboard_walk_stats(findings):

    counts = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counts[match] += 1

    return counts.most_common()

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

    if company_count > 0:

        company_text = (
            f"\n\nThe organisation name, or a variation thereof, "
            f"was identified within {company_count} recovered "
            f"passwords. Passwords that contain company-related "
            f"terms are particularly susceptible to targeted "
            f"guessing attacks and should be prioritised for remediation."
        )

    keyboard_text = ""

    if keyboard_count > 0:

        keyboard_text = (
            f"\n\n{keyboard_count} recovered passwords "
            f"were found to contain common keyboard "
            f"walking patterns."
        )

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

    results = {}

    results["admins"] = {
        "accounts": admins,
        "count": len(admins)
    }

    results["password_length"] = {
        "minimum_length": minimum_length,
        "failures": length_failures,
        "count": len(length_failures),
        "percentage": round(len(length_failures) / len(passwords) * 100, 1) if passwords else 0
    }

    results["top_passwords"] = {
        "passwords": top_passes,
        "count": len(top_passes)
    }

    results["company_words"] = {
        "count": len(company_findings),
        "accounts": company_findings,
        "stats": company_word_stats(company_findings),
        "company_words": company_words
    }

    results["keyboard_walks"] = {
        "count": len(keyboard_findings),
        "accounts": keyboard_findings,
        "stats": keyboard_walk_stats(keyboard_findings)
    }

    results["total_passwords"] = len(passwords)
    results["unique_passwords"] = len(set(p["password"]for p in passwords))

    print()
    print(executive_summary(results))
    print()

    print(f"Passwords Analysed : {results['total_passwords']}")
    print(f"Compromised Admins : {results['admins']['count']}")
    print(f"Unique Passwords   : {results['unique_passwords']}")
    print(f"Company-related Words : {results['company_words']['count']}")
    print(f"Keyboard Walks : {results['keyboard_walks']['count']}")


if __name__ == "__main__":
    main()