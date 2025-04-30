import os
import re
import socket
import requests
import json

# Slack Credentials from environment
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')
SLACK_CHANNEL = os.getenv('SLACK_CHANNEL')
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')

# Update to the server's Trivy scan directory
SCAN_DIR = "/home/ubuntu/trivy"  # Update this to the Trivy directory on your server
SERVER_NAME = socket.gethostname()


def extract_summary(file_path):
    summary_lines = []
    with open(file_path, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line and i + 2 < len(lines):
            if re.match(r"^=+$", lines[i + 1].strip()) and lines[i + 2].strip().startswith("Total:"):
                section = f"{line}\n{lines[i + 1].strip()}\n{lines[i + 2].strip()}"
                summary_lines.append(section)
                i += 3
            else:
                i += 1
        else:
            i += 1
    return summary_lines


def generate_blocks(server_name, scan_summaries):
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔍 Trivy Scan Summary"}
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Server:* `{server_name}`"}
        },
        {"type": "divider"}
    ]

    for filename, summaries in scan_summaries.items():
        if not summaries:
            continue

        summary_text = "\n\n".join(summaries)
        if len(summary_text) > 2900:
            summary_text = summary_text[:2900] + "\n... (truncated)"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*📁 {filename}*\n```{summary_text}```"
            }
        })
        blocks.append({"type": "divider"})

    return blocks


def send_to_slack(blocks):
    payload = {"blocks": blocks}
    response = requests.post(SLACK_WEBHOOK_URL, json=payload)
    if response.status_code != 200:
        print("Payload sent:\n", json.dumps(payload, indent=2))
        raise Exception(f"Slack send failed: {response.status_code}, {response.text}")


def main():
    scan_summaries = {}

    # Get the latest timestamped directory under /home/ubuntu/trivy
    latest_dir = max(
        [d for d in os.listdir(SCAN_DIR) if os.path.isdir(os.path.join(SCAN_DIR, d))],
        key=lambda d: os.path.getctime(os.path.join(SCAN_DIR, d))
    )
    latest_dir_path = os.path.join(SCAN_DIR, latest_dir)

    # Process each scan file in the latest directory
    for filename in os.listdir(latest_dir_path):
        file_path = os.path.join(latest_dir_path, filename)
        if os.path.isfile(file_path) and filename.endswith('.txt'):
            summaries = extract_summary(file_path)
            scan_summaries[filename] = summaries

    # Generate Slack message blocks
    blocks = generate_blocks(SERVER_NAME, scan_summaries)
    
    # Send the result to Slack
    send_to_slack(blocks)


if __name__ == "__main__":
    main()
