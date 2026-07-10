import os
from google import genai
from google.genai import types

def verify_findings_with_ai(findings_text, api_key):
    """
    Uses Gemini 2.5 Flash with Google Search Grounding to verify document findings.
    """
    try:
        # Initialize client with the provided API key
        client = genai.Client(api_key=api_key)
        
        prompt = f"""
You are an expert AI Document Fraud Investigator. 
I have analyzed a document and found the following anomalies and flags:

{findings_text}

1. Verify individuals: Check if mentioned names (e.g., in missing signatures) belong to the mentioned companies. **CRITICAL:** You MUST aggressively cross-check each person's name against ALL companies mentioned in the document flags (Akesis, Radiosurgery Global, and especially MagnetTx). 
   - Explicitly execute searches like: `"Roger Jewett" "MagnetTx"` and `"Jean-Luc Devleeschauwer" "MagnetTx"`.
   - If you cannot find them initially, you MUST use targeted search operators like `site:magnettx.com "Roger Jewett"` or `site:linkedin.com "Roger Jewett" MagnetTx`. 
2. Verify companies: Check if foreign company names found in metadata (e.g., MagnetTx) have any known relationships (mergers, partnerships, parent company) with the primary companies (e.g., Akesis, Radiosurgery Global). 
   - Explicitly execute searches like: `"MagnetTx" "Akesis" partnership` and `"MagnetTx" "Akesis" alliance`.
3. Ignore purely offline/internal recommendations like "Ask for the original Word document" or "Check for text overlay." Focus ONLY on what can be searched on the web.

You MUST output your response in strict, valid JSON format exactly matching the following structure. Do NOT wrap it in markdown ticks (```json):
{{
  "individuals": [
    {{
      "name": "Person Name",
      "findings": "Findings regarding this person and all companies. Was there a match?",
      "sources": ["URL 1", "URL 2"]
    }}
  ],
  "companies": [
    {{
      "name": "Company Name",
      "findings": "Findings regarding partnerships or connections",
      "sources": ["URL 1", "URL 2"]
    }}
  ],
  "conclusion": "Brief summary of whether these findings explain the anomalies or if they remain suspicious"
}}
"""
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,
                tools=[{"google_search": {}}],
            )
        )
        return response.text
    except Exception as e:
        return f"AI Verification failed: {str(e)}"
