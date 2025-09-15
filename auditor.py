import requests
from bs4 import BeautifulSoup

def analyze_website(url):
    """
    Main function to run all analysis checks on a given URL.
    """
    print(f"\nAnalyzing {url}...\n")

    try:
        # Fetch the website content
        response = requests.get(url, timeout=10)
        # Stop if the website is down or there's an error
        response.raise_for_status() 
    except requests.RequestException as e:
        print(f"Error: Could not fetch the website. {e}")
        return

    # Create a BeautifulSoup object to parse the HTML
    soup = BeautifulSoup(response.content, 'html.parser')

    # --- Run Checks ---
    check_https(url)
    check_title_tag(soup)
    check_h1_tag(soup)


def check_https(url):
    """Security Check: Checks if the website uses HTTPS."""
    print("--- Security Checks ---")
    if url.startswith("https://"):
        print("✅ OK: Website uses HTTPS.")
    else:
        print("❌ FAIL: Website does not use HTTPS. This is a major security risk.")

def check_title_tag(soup):
    """SEO Check: Checks for the presence and length of the title tag."""
    print("\n--- SEO Checks ---")
    title_tag = soup.find('title')
    
    if title_tag and title_tag.string:
        title_length = len(title_tag.string)
        print(f"✅ OK: Title tag found: \"{title_tag.string}\"")
        if 50 <= title_length <= 60:
            print(f"   - Good length ({title_length} characters).")
        else:
            print(f"   - Warning: Title length is {title_length}. Ideal is 50-60 characters.")
    else:
        print("❌ FAIL: No <title> tag found. This is critical for SEO.")

def check_h1_tag(soup):
    """SEO Check: Checks for the presence of a single H1 tag."""
    h1_tags = soup.find_all('h1')
    
    if len(h1_tags) == 1:
        print(f"✅ OK: Exactly one <h1> tag found: \"{h1_tags[0].string.strip()}\"")
    elif len(h1_tags) > 1:
        print(f"❌ FAIL: Found {len(h1_tags)} <h1> tags. There should only be one.")
    else:
        print("❌ FAIL: No <h1> tag found. This is important for SEO.")


if __name__ == "__main__":
    target_url = "https://www.google.com"  #<-- CHANGE THIS to the site you want to test!
    analyze_website(target_url)
