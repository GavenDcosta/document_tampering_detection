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

Your task is to use Google Search to verify the web-verifiable claims in these findings. 
Specifically:
1. Verify individuals: Check if mentioned names (e.g., in missing signatures) belong to the mentioned companies. **CRITICAL:** Cross-check each person's name against ALL companies mentioned in the document flags (e.g., check if Roger Jewett is the CFO of MagnetTx, not just Akesis). Check LinkedIn or news.
2. Verify companies: Check if foreign company names found in metadata (e.g., MagnetTx) have any known relationships (mergers, partnerships, parent company) with the primary companies (e.g., Akesis, Radiosurgery Global). 
3. Cite your sources: Provide the URL links to the LinkedIn profiles, news articles, or company pages you used to verify these claims.
4. Ignore purely offline/internal recommendations like "Ask for the original Word document" or "Check for text overlay." Focus ONLY on what can be searched on the web.

Provide a concise, professional report of your web verification results. Be clear about what you could confirm, what you couldn't, and what it implies. ALWAYS include source URLs.
"""
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                tools=[{"google_search": {}}],
            )
        )
        return response.text
    except Exception as e:
        return f"AI Verification failed: {str(e)}"
