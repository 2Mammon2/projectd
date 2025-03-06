import os
import requests
import subprocess

# Hàm chạy lệnh hệ thống với xử lý lỗi tự động
def run_command(command, fix_function=None):
    print(f"\n[+] Đang thực thi: {command}")
    
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout + result.stderr
        
        if result.returncode != 0:
            print("\n[-] Lệnh gặp lỗi:")
            print(output)
            if fix_function:
                print("\n[⚙️] AI đang cố gắng sửa lỗi và chạy lại...")
                fix_function()
        else:
            print(output)
    
    except Exception as e:
        print(f"[-] Lỗi hệ thống: {e}")
# Hàm loại bỏ http:// hoặc https:// từ URL
def extract_domain(target):
    """ Loại bỏ http:// hoặc https:// nếu có """
    return target.replace("https://", "").replace("http://", "").split('/')[0]

def scan_nmap(target):
    """ Quét port và dịch vụ bằng Nmap """
    clean_target = extract_domain(target)  # Loại bỏ https:// hoặc http://
    
    print("\n[+] Đang quét Port và Service bằng Nmap...")
    
    command = f"nmap -sV -Pn {clean_target}"
    print(f"\n[+] Đang thực thi: {command}")
    
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout + result.stderr
        
        if result.returncode != 0:
            print("\n[-] Lệnh gặp lỗi:")
            print(output)
            return
        
        print("\n[+] Kết quả quét:")
        print(output)

        # 🔥 Trích xuất danh sách port & dịch vụ từ kết quả Nmap
        ports = re.findall(r"(\d+/tcp)\s+open\s+(\S+)", output)
        if ports:
            print("\n[📌] Danh sách cổng mở & dịch vụ phát hiện được:")
            for port, service in ports:
                print(f"- Cổng: {port} | Dịch vụ: {service}")
        else:
            print("\n[-] Không tìm thấy cổng mở nào.")

    except Exception as e:
        print(f"[-] Lỗi hệ thống: {e}")

# 🔥 AI tự động sửa lỗi nếu gặp lỗi khi quét Misconfiguration
def fix_misconfig_scan(target):
    print("\n[AI] Đang thử thay thế `http-config-check.nse` bằng `http-enum.nse`, `http-headers.nse`, `http-vuln*`...")
    run_command(f"nmap --script=http-enum,http-headers,http-vuln* {target}")

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
    run_command(f"nmap --script=http-config-check.nse {target}", fix_function=lambda: fix_misconfig_scan(target))

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
        
        # Gợi ý quét phù hợp
        print("\n[💡] Gợi ý quét phù hợp:")
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
