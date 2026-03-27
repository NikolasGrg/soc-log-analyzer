def analyze_logs(file):
    suspicious = []

    with open(file, 'r') as f:
        for line in f:
            if "failed" in line.lower() or "error" in line.lower():
                suspicious.append(line.strip())

    return suspicious


if __name__ == "__main__":
    results = analyze_logs("sample_logs.txt")

    print("Suspicious Events:")
    for r in results:
        print(r)
