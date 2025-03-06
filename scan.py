import os
import requests
import re

# Hàm chạy lệnh hệ thống
def run_command(command):
    print(f"\n[+] Đang thực thi: {command}")
    os.system(command)

# Hàm quét Port và Service bằng Nmap
def scan_nmap(target):
    print("\n[+] Đang quét Port và Service bằng Nmap...")
    run_command(f"nmap -sV -Pn {target}")

# Hàm quét XSS bằng XSStrike
def scan_xss(target):
    print("\n[+] Đang quét XSS bằng XSStrike...")
    run_command(f"python3 XSStrike/xsstrike.py -u {target}")

# Hàm quét bảo mật web bằng Nikto
def scan_nikto(target):
    print("\n[+] Đang quét bảo mật Webserver bằng Nikto...")
    run_command(f"nikto -h {target}")

# Hàm quét SSRF bằng SSRFmap
def scan_ssrf(target):
    print("\n[+] Đang kiểm tra SSRF bằng SSRFmap...")
    run_command(f"python3 SSRFmap/ssrfmap.py -u {target}")

# Hàm quét Misconfiguration
def scan_misconfiguration(target):
    print("\n[+] Đang kiểm tra lỗi cấu hình sai...")
    run_command(f"nmap --script=http-config-check.nse {target}")

# Hàm quét SQL Injection bằng SQLMap
def scan_sqli(target):
    print("\n[+] Đang kiểm tra SQL Injection bằng SQLMap...")
    run_command(f"sqlmap -u {target} --dbs --batch")

# 🔥 AI tự động tìm hiểu mục tiêu
def analyze_target(target):
    print("\n[🔍] Đang phân tích mục tiêu với AI...")
    try:
        headers = requests.get(target).headers
        print("[+] Headers thu thập được:", headers)

        # Xác định công nghệ web
        tech_stack = []
        if "X-Powered-By" in headers:
            tech_stack.append(headers["X-Powered-By"])
        if "Server" in headers:
            tech_stack.append(headers["Server"])
        if not tech_stack:
            tech_stack.append("Không xác định")

        print(f"[+] Công nghệ web phát hiện: {', '.join(tech_stack)}")

        # Xác định CMS (WordPress, Joomla, v.v.)
        cms_detected = None
        html = requests.get(target).text
        if "wp-content" in html:
            cms_detected = "WordPress"
        elif "Joomla" in html:
            cms_detected = "Joomla"
        elif "Drupal" in html:
            cms_detected = "Drupal"
        
        if cms_detected:
            print(f"[+] Phát hiện CMS: {cms_detected}")
        
        # Gợi ý phương pháp tấn công
        print("\n[💡] Gợi ý tấn công phù hợp:")
        if "PHP" in tech_stack or cms_detected in ["WordPress", "Joomla"]:
            print("- Có thể có SQLi. Khuyến nghị quét SQLMap.")
        if "nginx" in tech_stack or "Apache" in tech_stack:
            print("- Có thể có cấu hình sai. Khuyến nghị kiểm tra Misconfiguration.")
        if cms_detected == "WordPress":
            print("- Kiểm tra plugin & theme bằng WPScan.")

    except Exception as e:
        print(f"[-] Lỗi khi phân tích mục tiêu: {e}")

# Menu chọn kiểu quét
def main():
    print("===================================")
    print("   TOOL PENTEST WEB SERVER AI")
    print("===================================")
    
    target = input("Nhập URL/IP mục tiêu: ").strip()

    # 🔥 Tự động phân tích trước khi quét
    analyze_target(target)

    while True:
        print("\nChọn kiểu quét:")
        print("1. Quét Port và Service (Nmap)")
        print("2. Quét XSS (XSStrike)")
        print("3. Quét bảo mật Webserver (Nikto)")
        print("4. Quét SSRF (SSRFmap)")
        print("5. Kiểm tra lỗi cấu hình sai (Misconfiguration)")
        print("6. Quét SQL Injection (SQLMap)")
        print("99. Thoát tool")
        
        choice = input("Nhập lựa chọn: ").strip()
        
        if choice == "1":
            scan_nmap(target)
        elif choice == "2":
            scan_xss(target)
        elif choice == "3":
            scan_nikto(target)
        elif choice == "4":
            scan_ssrf(target)
        elif choice == "5":
            scan_misconfiguration(target)
        elif choice == "6":
            scan_sqli(target)
        elif choice == "99":
            print("\n[+] Thoát tool. Hẹn gặp lại!")
            break
        else:
            print("\n[-] Lựa chọn không hợp lệ, vui lòng nhập lại.")

if __name__ == "__main__":
    main()
