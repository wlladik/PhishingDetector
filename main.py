from src.detector import detect_phishing

SAMPLES_URLS = 'samples/safe_urls.txt'
SAMPLES_BAD_URLS = 'samples/phishing_urls.txt'
SAMPLES_EMAIL_TEXT = 'samples/phishing_emails.txt'


def analyze_file(filepath: str, is_url: bool = True):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return

    for item in lines:
        result = detect_phishing(url=item) if is_url else detect_phishing(text=item)
        print("\nInput:", item)
        print("Verdict:", result["verdict"])
        print("Risk score:", result["score"])
        print("Reasons:")
        for r in result["reasons"]:
            print("-", r)
        print("-" * 40)


def main():
    print("=== Phishing Detector ===")
    print("1 - Analyze URL")
    print("2 - Analyze email/text")
    print("3 - Analyze URL from samples (good)")
    print("4 - Analyze URL from samples (bad)")
    print("5 - Analyze email/text from samples")

    choice = input("Choose option: ")

    if choice == "1":
        url = input("Enter URL: ")
        result = detect_phishing(url=url)

        print("\nVerdict:", result["verdict"])
        print("Risk score:", result["score"])
        print("Reasons:")
        for r in result["reasons"]:
            print("-", r)

    elif choice == "2":
        text = input("Paste text:\n")
        result = detect_phishing(text=text)

        print("\nVerdict:", result["verdict"])
        print("Risk score:", result["score"])
        print("Reasons:")
        for r in result["reasons"]:
            print("-", r)

    elif choice == "3":
        analyze_file(SAMPLES_URLS, is_url=True)

    elif choice == "4":
        analyze_file(SAMPLES_BAD_URLS, is_url=True)

    elif choice == "5":
        analyze_file(SAMPLES_EMAIL_TEXT, is_url=False)

    else:
        print("Invalid option")
        return


if __name__ == "__main__":
    main()
