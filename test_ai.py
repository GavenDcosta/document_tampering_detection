import forensics_engine as fe
import ai_verifier
import os

pdf_path = r"..\Akesis RSG DA - final.pdf"
import os
import re

env_path = ".env"
api_key = None
if os.path.exists(env_path):
    with open(env_path, "r") as f:
        content = f.read()
        match = re.search(r'GOOGLE_API_KEY=(.*)', content)
        if match:
            api_key = match.group(1).strip()

if not api_key:
    api_key = os.environ.get("GOOGLE_API_KEY")

if not api_key:
    print("Please set GOOGLE_API_KEY in .env")
    exit(1)

print("1. Running forensics engine on Akesis document...")
result = fe.analyze_file(pdf_path)

findings_text = f"\nFile: {os.path.basename(pdf_path)}\n"
for f in result.get("findings", []):
    findings_text += f"- {f['title']}: {f.get('detail', '')}\n"

print("2. Findings generated:")
print(findings_text)

print("\n3. Sending to Gemini for Web Verification...")
ai_report = ai_verifier.verify_findings_with_ai(findings_text, api_key)

print("\n4. AI Verification Report:")
print(ai_report)
