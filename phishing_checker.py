
import csv
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "shorturl.at",
}

SUSPICIOUS_HOST_WORDS = {
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "signin",
}


def analyze_url(url):
    """Analyze URL text using simple heuristic rules."""
    url = url.strip()
    findings = []
    score = 0

    result = {
        "url": url,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "score": 0,
        "category": "Invalid Input",
        "findings": [],
    }

    if not url:
        result["findings"] = ["Please enter a URL."]
        return result

    # Reject whitespace inside a URL.
    if any(char.isspace() for char in url):
        result["findings"] = [
            "The URL contains spaces or whitespace."
        ]
        return result

    # Add a scheme when one is not supplied.
    if "://" not in url:
        url = "https://" + url
        result["url"] = url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        # Accessing port can raise ValueError for malformed ports.
        _ = parsed.port
    except ValueError:
        result["findings"] = [
            "The URL contains an invalid hostname or port."
        ]
        return result

    if parsed.scheme.lower() not in ("http", "https"):
        result["findings"] = [
            "Only HTTP and HTTPS URLs are supported."
        ]
        return result

    if not hostname:
        result["findings"] = [
            "Could not identify a hostname in this URL."
        ]
        return result

    hostname = hostname.lower().rstrip(".")

    # Rule 1: @ can make the destination confusing.
    if "@" in parsed.netloc:
        findings.append(
            "The URL contains '@'. Check the actual hostname carefully."
        )
        score += 25

    # Rule 2: Unusually long URL.
    if len(url) > 100:
        findings.append("The URL is unusually long.")
        score += 10

    # Rule 3: IP address used as the hostname.
    try:
        ipaddress.ip_address(hostname)
        findings.append(
            "The hostname is an IP address rather than a domain name."
        )
        score += 25
    except ValueError:
        pass

    # Rule 4: Many hostname labels or subdomains.
    if len(hostname.split(".")) >= 5:
        findings.append(
            "The hostname contains many subdomain labels."
        )
        score += 15

    # Rule 5: Punycode domain labels.
    if any(
        label.startswith("xn--")
        for label in hostname.split(".")
    ):
        findings.append(
            "The domain contains punycode; inspect it carefully."
        )
        score += 20

    # Rule 6: HTTP does not encrypt the connection.
    if parsed.scheme.lower() == "http":
        findings.append(
            "The URL uses HTTP instead of HTTPS."
        )
        score += 10

    # Rule 7: Known URL-shortening services.
    if any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in URL_SHORTENERS
    ):
        findings.append(
            "This hostname belongs to a known URL-shortening service. "
            "The final destination is not shown here."
        )
        score += 15

    # Rule 8: Suspicious words in the hostname.
    host_labels = set(re.split(r"[.-]", hostname))
    matched_words = host_labels.intersection(SUSPICIOUS_HOST_WORDS)

    if matched_words:
        words = ", ".join(sorted(matched_words))
        findings.append(
            f"The hostname contains potentially misleading words: {words}."
        )
        score += 10

    # Rule 9: Several percent-encoded sequences.
    encoded_parts = re.findall(r"%[0-9a-fA-F]{2}", url)

    if len(encoded_parts) >= 4:
        findings.append(
            "The URL contains several percent-encoded sequences."
        )
        score += 10

    score = min(score, 100)

    if score >= 60:
        category = "High"
    elif score >= 30:
        category = "Medium"
    else:
        category = "Low"

    if not findings:
        findings.append(
            "No suspicious indicators were detected by these rules."
        )

    result["score"] = score
    result["category"] = category
    result["findings"] = findings

    return result


def display_result(result):
    print("\n" + "=" * 50)
    print("URL:", result["url"])
    print("Risk score:", f'{result["score"]}/100')
    print("Risk category:", result["category"])
    print("Findings:")

    for finding in result["findings"]:
        print("-", finding)

    print(
        "\nReminder: this score is heuristic, not proof "
        "that a URL is safe or malicious."
    )
    print("=" * 50)


def export_csv(results):
    if not results:
        print("There are no scan results to export.")
        return

    filename = input(
        "Enter CSV filename (press Enter for scan_results.csv): "
    ).strip()

    if not filename:
        filename = "scan_results.csv"

    if not filename.lower().endswith(".csv"):
        filename += ".csv"

    try:
        with open(
            filename, "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "timestamp",
                    "url",
                    "score",
                    "category",
                    "findings",
                ],
            )
            writer.writeheader()

            for result in results:
                writer.writerow({
                    "timestamp": result["timestamp"],
                    "url": result["url"],
                    "score": result["score"],
                    "category": result["category"],
                    "findings": " | ".join(result["findings"]),
                })

        print(f"Report saved to: {filename}")

    except OSError as error:
        print("Could not save the report:", error)


def main():
    results = []

    print("====================================")
    print("       PHISHING URL CHECKER")
    print("====================================")
    print("This program analyzes URL text only.")
    print("It does not open or visit websites.")

    while True:
        print("\n1. Check one URL")
        print("2. Check multiple URLs")
        print("3. Export scan results to CSV")
        print("4. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            url = input("Enter URL: ")
            result = analyze_url(url)
            display_result(result)

            if url.strip():
                results.append(result)

        elif choice == "2":
            print("Enter one URL per line.")
            print("Press Enter on a blank line to finish.")

            batch_results = []

            while True:
                url = input("URL: ")

                if not url.strip():
                    break

                result = analyze_url(url)
                display_result(result)
                batch_results.append(result)

            results.extend(batch_results)
            print(f"Batch complete: {len(batch_results)} URL(s) checked.")

        elif choice == "3":
            export_csv(results)

        elif choice == "4":
            print("Thank you for using Phishing URL Checker!")
            break

        else:
            print("Invalid option. Please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
