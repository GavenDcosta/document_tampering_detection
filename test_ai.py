import forensics_engine as fe
import ai_verifier
import os

pdf_path = r"..\Akesis RSG DA - final.pdf"
api_key = os.environ.get("GOOGLE_API_KEY")

if not api_key:
    print("Please set GOOGLE_API_KEY environment variable")
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
