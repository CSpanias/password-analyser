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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COLOR_GREEN = "\033[0;32m"
COLOR_RED = "\033[0;31m"
COLOR_YELLOW = "\033[1;33m"
COLOR_CYAN = "\033[0;36m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

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

NUMBER_WORDS = {
    0: "zero",
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine"
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


def human_number(value):

    if value in NUMBER_WORDS:
        return NUMBER_WORDS[value]

    return str(value)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

# Recovered Domain Admins
def compromised_admins(passwords, domain_admins):

    admins = []
    admin_set = {user.lower().split("\\")[-1] for user in domain_admins}

    for record in passwords:
        username = (record["username"].lower().split("\\")[-1])

        if username in admin_set:
            admins.append(record)

    return admins


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


# Non-Compliant Passwords
def password_lengths(passwords):

    return Counter(len(record["password"]) for record in passwords)


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

def common_password_stats(findings):

    counter = Counter()

    for finding in findings:
        for match in finding["matches"]:
            counter[match] += 1

    return counter.most_common()


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

# ------------------
# Executive Summary
# ------------------

def executive_summary(results):

    total = results["total_passwords"]
    enabled_users = results["enabled_users"]
    admin_count = results["admins"]["count"]
    failure_count = results["password_length"]["count"]
    percentage = results["password_length"]["percentage"]
    minimum_length = results["password_length"]["minimum_length"]
    company_count = results["company_words"]["count"]
    username_count = results["username_passwords"]["count"]
    reuse_count = results["password_reuse"]["count"]
    common_count = results["common_passwords"]["count"]
    date_count = results["date_passwords"]["count"]
    keyboard_count = results["keyboard_walks"]["count"]
    crack_rate = results["crack_rate"]

    summary = []

    summary.append("A password audit was performed against extracted Active Directory password hashes to assess the "
        "effectiveness of password selection practices and identify weaknesses that could increase the likelihood "
        "of credential compromise.")

    summary.append(
        f"Through password-cracking techniques, it was possible to recover {total} plaintext passwords from "
        f"{enabled_users:,} enabled user accounts, representing approximately {crack_rate}% of the assessed population. "
        "This demonstrates that a measurable proportion of user credentials remain susceptible to password-cracking "
        "attacks following credential exposure.")

    weaknesses = []

    if company_count:
        weaknesses.append("organisation-related terminology")

    if common_count:
        weaknesses.append("common password phrases")

    if date_count:
        weaknesses.append("date-based passwords")

    if keyboard_count:
        weaknesses.append("keyboard sequences")

    if username_count:
        weaknesses.append("username-derived passwords")

    if reuse_count:
        weaknesses.append("password reuse between related accounts")

    if weaknesses:

        summary.append("The assessment identified recurring weaknesses relating to password selection practices. A "
            "significant proportion of recovered credentials were found to follow predictable construction "
            "patterns, reducing password entropy and increasing susceptibility to password guessing, password "
            "spraying, and offline password-cracking attacks.")

    if admin_count:

        summary.append(f"Password weaknesses were also identified within privileged identities, resulting in the "
            f"successful recovery of {human_number(admin_count)} Domain Administrator password{'s' if admin_count > 1 else ''}. "
            "Such identities represent high-value targets due to the elevated level of access they provide "
            "across the environment. Their compromise would substantially increase the potential impact of a successful attack.")

    if failure_count:

        summary.append(f"The domain enforced a minimum password length requirement of {human_number(minimum_length)} characters. "
            f"However, analysis of the recovered credentials identified {failure_count} passwords "
            f"({percentage}% of recovered passwords) that did not comply with this requirement, "
            "indicating that weak, legacy, or otherwise non-compliant credentials remain present within the environment.")

    summary.append("Overall, the results indicate that password complexity and selection practices could be further improved. "
        "Strengthening password policy enforcement, reducing the use of predictable password patterns, and ensuring "
        "privileged accounts utilise unique, high-entropy passwords will reduce the likelihood of successful "
        "credential-based attacks and improve the overall resilience of the organisation's identity infrastructure.")

    return "\n\n".join(summary)

# ---------------------
# Technical Commentary
# ---------------------

def commentary_admins(results):

    admins = (results["admins"]["accounts"])
    count = (results["admins"]["count"])

    if not count:

        return ("No Domain Administrator passwords were successfully recovered during the password audit. "
            "This is a positive outcome, as privileged accounts represent high-value targets and their compromise "
            "would significantly increase the potential impact of a successful attack.")

    lines = []

    lines.append(f"{human_number(count).capitalize()} Domain Administrator "
        f"account{'s were' if count > 1 else ' was'} successfully recovered during the password audit.")
    lines.append("")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in admins:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")
    lines.append("")

    return "\n".join(lines)


def commentary_password_lengths(results):

    minimum_length = results["password_length"]["minimum_length"]
    failures = results["password_length"]["failures"]
    failure_count = results["password_length"]["count"]
    failure_percentage = results["password_length"]["percentage"]

    lengths = results["password_lengths"]["lengths"]
    total_passwords = results["total_passwords"]

    if not lengths:
        return ""

    most_common_length = max(lengths, key=lambda item: item[1])[0]
    lines = []

    if failure_count:
        distribution = Counter(failure["length"] for failure in failures)
        most_common = distribution.most_common()
        highest = most_common[0][1]
        common_lengths = [str(length) for length, frequency in most_common if frequency == highest]
        top_lengths = " and ".join(common_lengths)

        lines.append(f"The domain enforced a minimum password length requirement of {minimum_length} characters. "
            f"Analysis of the recovered credentials identified {failure_count} passwords ({failure_percentage}% "
            "of recovered passwords) that did not comply with this requirement. The most frequently observed "
            f"non-compliant password length{'s were' if len(common_lengths) > 1 else ' was'} "
            f"{top_lengths} character{'s' if len(common_lengths) == 1 else ''}, while the most commonly observed password length "
            f"overall was {most_common_length} characters.")
        lines.append("")

    else:
        lines.append("All recovered passwords complied with the configured minimum password length requirement "
            f"of {minimum_length} characters. This indicates effective enforcement of the domain password "
            f"policy. The most commonly observed password length was {most_common_length} characters.")

        lines.append("")

    lines.append("The following password length distribution was observed across the recovered credentials:")
    lines.append("")

    lines.append("| Length | Count | Percentage |")
    lines.append("| ---------- | ---------- | ---------- |")

    for length, count in sorted(lengths):

        percentage = round(count / total_passwords * 100, 1)
        lines.append(f"| {length} | {count} | {percentage}% |")

    lines.append("")

    return "\n".join(lines)


def commentary_password_reuse(results):

    reused_passwords = []

    for password, count in (results["password_frequency"]["passwords"]):
        if count < 2:
            continue

        reused_passwords.append({"password": password,"count": count})

    if not reused_passwords:
        return ("No password reuse was identified between similarly named accounts. This suggests that privileged and "
            "standard user accounts are generally configured with unique credentials, reducing the risk of "
            "privilege escalation following credential compromise.")

    lines = []

    lines.append(
        "Analysis of the recovered credentials identified several passwords that were reused across multiple "
        "accounts. Password reuse increases the impact of credential compromise, as a single recovered password "
        "may provide access to multiple systems, services, or user accounts.")

    lines.append("")

    lines.append("| Password | Times Seen | Percentage |")
    lines.append("| ---------- | ---------- | ---------- |")

    total_passwords = results["total_passwords"]

    for entry in reused_passwords[:10]:
        percentage = round(entry["count"] / total_passwords * 100, 1)
        lines.append(f"| {mask_password(entry['password'])} | {entry['count']} | {percentage}% |")
    
    lines.append("")

    return "\n".join(lines)

def commentary_similar_account_reuse(results):

    reuse_accounts = (results["password_reuse"]["accounts"])
    count = (results["password_reuse"]["count"])

    if not count:

        return ("No recovered passwords were identified as containing the username or an obvious variation thereof. This "
            "reduces susceptibility to targeted password guessing attacks that leverage user-specific information.")

    lines = []

    lines.append(
        f"{human_number(count).capitalize()} account pair{'s were' if count > 1 else ' was'} "
        "identified as sharing passwords between similarly named accounts. This behaviour is "
        "commonly observed where standard and privileged accounts are operated by the same individual or "
        "service. Password reuse increases the impact of credential compromise and may facilitate privilege "
        "escalation or lateral movement.")

    lines.append("")
    lines.append("| Username | Password | Shared With |")
    lines.append("| ---------- | ---------- | ---------- |")

    for account in reuse_accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} | {account['shared_with']} |")

    lines.append("")

    return "\n".join(lines)


def commentary_username_passwords(results):

    accounts = (results["username_passwords"]["accounts"])
    count = (results["username_passwords"]["count"])

    if not count:
        return ""

    lines = []

    lines.append(f"{human_number(count).capitalize()} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing the username or a variation thereof. Passwords incorporating username-related "
        "information reduce password entropy and may be more easily predicted by an attacker.")

    lines.append("")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    lines.append("")

    return "\n".join(lines)


def commentary_company_words(results):

    accounts = results["company_words"]["accounts"]
    count = results["company_words"]["count"]
    stats = results["company_words"]["stats"]

    if not count:

        return ("No recovered passwords were identified as containing organisation-related terminology. This reduces the "
            "effectiveness of targeted password guessing attacks that utilise publicly available organisational information.")

    lines = []

    lines.append(
        f"The organisation name, or a variation thereof, was identified within {human_number(count)} recovered "
        f"password{'s' if count != 1 else ''}. Organisation-specific terminology may be inferred from publicly "
        "available information and can therefore increase exposure to targeted authentication attacks.")

    lines.append("")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:
        lines.append("")
        lines.append("The following organisation-related terms were identified most frequently within recovered passwords:")
        lines.append("")

        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats:
            lines.append(f"| {term} | {frequency} |")

    lines.append("")

    return "\n".join(lines)


def commentary_date_passwords(results):

    accounts = results["date_passwords"]["accounts"]
    count = results["date_passwords"]["count"]
    stats = results["date_passwords"]["stats"]

    if not count:

        return ("No recovered passwords were identified as containing date-related terminology such as days, months, or "
            "seasons. This reduces reliance on predictable and easily guessable password construction patterns.")

    lines = []

    lines.append(f"{human_number(count).capitalize()} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing references to days, months, seasons, or other date-related terms. "
        "Dates, seasons, and similar memorable references are commonly used to improve memorability "
        "but result in predictable password construction patterns.")

    lines.append("")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:

        lines.append("")
        lines.append("The following date-related terms were identified most frequently within recovered passwords:")
        lines.append("")

        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats:
            lines.append(f"| {term} | {frequency} |")

    lines.append("")

    return "\n".join(lines)


def commentary_keyboard_walks(results):

    accounts = results["keyboard_walks"]["accounts"]
    count = results["keyboard_walks"]["count"]
    stats = results["keyboard_walks"]["stats"]

    if not count:

        return ("No recovered passwords were identified as containing keyboard walking patterns. Such patterns are "
            "commonly included within password-cracking rule sets and their absence represents a positive indicator of password quality.")

    lines = []

    lines.append(f"{human_number(count).capitalize()} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing keyboard walking patterns. Keyboard sequences are widely represented within password "
        "auditing wordlists and cracking rule sets due to their predictable structure.")

    lines.append("")
    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:
        lines.append("")
        lines.append("The following keyboard walk patterns were identified most frequently:")
        lines.append("")

        lines.append("| Pattern | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for pattern, frequency in stats:
            lines.append(f"| {pattern} | {frequency} |")

        lines.append("")

    return "\n".join(lines)


def commentary_common_passwords(results):

    accounts = results["common_passwords"]["accounts"]
    count = results["common_passwords"]["count"]
    stats = results["common_passwords"]["stats"]

    if not count:

        return ("No recovered passwords were identified as containing commonly used password terms or well-known weak "
            "password variants. This suggests that users are generally avoiding predictable password selections "
            "that are commonly represented within attacker wordlists.")

    lines = []

    lines.append(f"A total of {human_number(count).capitalize()} recovered password{'s were' if count != 1 else ' was'} "
        "identified as containing commonly used password terms or variants thereof. Common password terms remain prevalent "
        "within publicly available breach corpora and are routinely prioritised during password attacks.")

    lines.append("")

    lines.append("| Username | Password |")
    lines.append("| ---------- | ---------- |")

    for account in accounts:
        lines.append(f"| {account['username']} | {mask_password(account['password'])} |")

    if stats:

        lines.append("")
        lines.append("The following common password terms were identified most frequently:")
        lines.append("")

        lines.append("| Term | Occurrences |")
        lines.append("| ---------- | ---------- |")

        for term, frequency in stats:
            lines.append(f"| {term} | {frequency} |")

    lines.append("")

    return "\n".join(lines)


def commentary_character_classes(results):

    stats = results["character_classes"]

    lines = []

    lines.append("Recovered passwords were analysed to determine the adoption of common character classes. Whilst the "
        "presence of uppercase characters, numbers, and special characters may increase password complexity, "
        "their use alone does not guarantee resistance to password guessing or password-cracking attacks.")

    lines.append("")

    lines.append("| Character Type | Adoption (%) |")
    lines.append("| ---------- | ---------- |")

    lines.append(f"| Lowercase | {stats['lower']} |")
    lines.append(f"| Uppercase | {stats['upper']} |")
    lines.append(f"| Numeric   | {stats['numeric']} |")
    lines.append(f"| Special   | {stats['special']} |")

    lines.append("")

    return "\n".join(lines)


def technical_commentary(results):

    lines = []

    total = results["total_passwords"]

    lines.append("A password audit was performed against extracted password hashes. Password-cracking techniques "
        "were used to recover plaintext credentials and, as such, not all passwords were expected to be "
        f"identified within a reasonable timeframe. In total, {total} username and password combinations were successfully recovered and analysed.")
    lines.append("")
    lines.append(commentary_admins(results))
    lines.append(commentary_password_lengths(results))
    lines.append(commentary_password_reuse(results))
    lines.append(commentary_similar_account_reuse(results))
    lines.append(commentary_username_passwords(results))
    lines.append(commentary_company_words(results))
    lines.append(commentary_date_passwords(results))
    lines.append(commentary_keyboard_walks(results))
    lines.append(commentary_common_passwords(results))
    lines.append(commentary_character_classes(results))

    return "\n".join(lines)


# ---------------------
# Remediation Guidance
# ---------------------

def remediation_guidance(results):

    lines = []

    # ------------------------
    # Administrative Accounts
    # ------------------------

    if (results["admins"]["count"] or results["password_reuse"]["count"]):

        lines.append("Administrative and other highly privileged accounts should utilise unique, high-entropy passwords that "
            "are not shared with standard user accounts. Where possible, a separate password policy should be "
            "applied to privileged identities, enforcing a minimum password length of at least 15 "
            "characters and preventing password reuse between account types.")

        lines.append("")

    # ----------------------
    # Password Construction
    # ----------------------

    if (
        results["company_words"]["count"]
        or results["username_passwords"]["count"]
        or results["date_passwords"]["count"]
        or results["common_passwords"]["count"]
        or results["keyboard_walks"]["count"]
    ):

        lines.append("A number of recovered passwords were identified as containing predictable elements, including commonly "
            "used password terms, organisation-related terminology, date-related references, keyboard sequences, and username-derived content."
            "Users should be encouraged to select passwords that are unrelated to personal information, organisational terminology, or other "
            "predictable patterns. Technical controls such as password filtering solutions should also be considered to prevent the use of "
            "insecure or commonly observed password constructions.")

        lines.append("")

    # -------------------------------
    # Password Length and Complexity
    # -------------------------------

    if results["password_length"]["count"]:

        lines.append("Several recovered passwords did not comply with the configured minimum password length requirement. "
            "Password policy settings should be reviewed to ensure that all accounts meet the organisation's "
            "baseline security requirements and that legacy or non-compliant credentials are remediated. Longer passwords and "
            "passphrases generally provide greater resistance to offline password-cracking attacks and should be encouraged wherever possible.")

        lines.append("")

    # ---------------
    # Password Reuse
    # ---------------

    reused = any(count > 1 for _, count in results["password_frequency"]["passwords"])

    if reused:

        lines.append("Password reuse was identified across multiple accounts. Users should be encouraged to maintain "
            "unique passwords for all accounts and services. Password filtering solutions capable of screening previously "
            "disclosed or commonly reused passwords should be considered as an additional preventative control.")

        lines.append("")

    # ----------------------------
    # Multi-Factor Authentication
    # ----------------------------

    lines.append("Regardless of the specific weaknesses identified, multi-factor authentication should be enforced for "
        "all externally accessible services and privileged accounts wherever technically feasible. Whilst strong "
        "passwords remain important, multi-factor authentication provides additional protection "
        "against password-based attacks and reduces the likelihood of account compromise following credential exposure.")

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description="Password Audit")

    parser.add_argument("-M", "--mapped-passwords", required=True, help="mapped-passwords.txt")
    parser.add_argument("-A", "--domain-admins", default="./ntds-organiser/domain-admins.txt", help="domain-admins.txt (default: ./ntds-organiser/domain-admins.txt)")
    parser.add_argument("-P", "--pass-policy", default="./ntds-organiser/domain-policy.txt", help="domain-policy.txt (default: ./ntds-organiser/domain-policy.txt)")
    parser.add_argument("-C", "--company-words", help="File containing company-related words")
    parser.add_argument("-E", "--enabled-users", default="./ntds-organiser/enabled-users.txt", help="enabled-users.txt (default: ./ntds-organiser/enabled-users.txt)")

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
    enabled_users = load_list(args.enabled_users)

    results = {}

    results["admins"] = {"accounts": admins,"count": len(admins)}
    results["password_length"] = {"minimum_length": minimum_length, "failures": length_failures, "count": len(length_failures), "percentage": round(len(length_failures) / len(passwords) * 100) if passwords else 0}
    results["top_passwords"] = {"passwords": top_passes, "count": len(top_passes)}
    results["company_words"] = {"count": len(company_findings), "accounts": company_findings, "stats": company_word_stats(company_findings), "company_words": company_words}
    results["keyboard_walks"] = {"count": len(keyboard_findings), "accounts": keyboard_findings, "stats": keyboard_walk_stats(keyboard_findings)}
    results["total_passwords"] = len(passwords)
    results["unique_passwords"] = len(set(p["password"]for p in passwords))
    results["username_passwords"] = {"count": len(username_findings), "accounts": username_findings}
    results["password_reuse"] = {"count": len(reuse_findings), "accounts": reuse_findings}
    results["common_passwords"] = {"count": len(common_password_findings), "accounts": common_password_findings, "stats": common_password_stats(common_password_findings)}
    results["date_passwords"] = {"count": len(date_findings), "accounts": date_findings, "stats": date_stats(date_findings)}
    results["password_frequency"] = {"passwords": password_frequencies}
    results["character_classes"] = (char_classes)
    results["password_lengths"] = {"lengths": length_distribution}
    results["enabled_users"] = len(enabled_users)
    results["crack_rate"] = round(results["total_passwords"] / results["enabled_users"] * 100, 1)

    print()
    print(f"{COLOR_CYAN}=== EXECUTIVE SUMMARY ==={COLOR_RESET}")
    print()
    print(executive_summary(results))

    print()
    print(f"{COLOR_CYAN}=== TECHNICAL COMMENTARY ==={COLOR_RESET}")
    print()
    print(technical_commentary(results))

    print()
    print(f"{COLOR_CYAN}=== REMEDIATION GUIDANCE ==={COLOR_RESET}")
    print()
    print(remediation_guidance(results))

if __name__ == "__main__":
    main()