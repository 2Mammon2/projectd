import os
import requests
import subprocess
import re
import socket
from urllib.parse import urlparse, urljoin
import random

#-----------------------------------------------#
# Hàm xử lý
def get_latest_user_agents():
    url = "https://raw.githubusercontent.com/tamimibrahim17/List-of-user-agents/master/user-agents.txt"

    try:
        response = requests.get(url)
        user_agents = response.text.split("\n")
        return [ua.strip() for ua in user_agents if ua.strip()]
    except requests.RequestException as e:
        print(f"❌ Lỗi kết nối API: {e}")
        return []

# Lấy danh sách User-Agent mới nhất
latest_ua_list = get_latest_user_agents()

# Chọn User-Agent ngẫu nhiên
if latest_ua_list:
    random_ua = random.choice(latest_ua_list)
    print(f"✅ User-Agent ngẫu nhiên: {random_ua}")
else:
    print("⚠ Không có User-Agent nào được lấy từ API!")

# Hàm yêu cầu người dùng nhập URL/IP mục tiêu và kiểm tra tính hợp lệ
def get_valid_target():
    while True:
        target = input("Nhập URL/IP mục tiêu: ").strip()

        # Nếu người dùng nhập IP trực tiếp, không cần kiểm tra URL
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        
        # Nếu thiếu scheme (http:// hoặc https://), thêm mặc định
        if not target.startswith(("http://", "https://")):
            print(f"[-] URL thiếu scheme, tự động thêm 'https://': {target}")
            target = "https://" + target
        
        # Kiểm tra tính hợp lệ bằng request
        try:
            response = requests.get(target, timeout=5)
            if response.status_code == 200:
                return target
            else:
                print(f"[-] URL không hợp lệ hoặc không thể kết nối! (Mã lỗi: {response.status_code})")
        except requests.exceptions.RequestException:
            print("[-] Không thể kết nối đến URL! Vui lòng kiểm tra và nhập lại.")
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

def clean_target_url(target):
    """ Loại bỏ https://, http://, dấu /, ? và tham số """
    clean_target = re.sub(r"https?://", "", target)  # Xóa http:// hoặc https://
    clean_target = clean_target.split('/')[0]  # Lấy phần tên miền chính
    clean_target = clean_target.split('?')[0]  # Loại bỏ các tham số URL nếu có
    return clean_target

def resolve_domain(domain):
    """ Kiểm tra xem tên miền có hợp lệ không """
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Tên miền hợp lệ! Địa chỉ IP: {ip}")
        return ip
    except socket.gaierror:
        print("[-] Không thể phân giải tên miền. Vui lòng nhập địa chỉ IP trực tiếp.")
        return None
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

#-----------------------------------------------#
# Hàm quét port và dịch vụ bằng Nmap 
def scan_nmap(target):
    """ Quét port và dịch vụ bằng Nmap """
    clean_target = clean_target_url(target)  # Làm sạch URL

    # Kiểm tra xem có thể phân giải tên miền không
    ip_target = resolve_domain(clean_target)
    if not ip_target:
        ip_target = input("[!] Nhập địa chỉ IP của mục tiêu: ").strip()

    print("\n[+] Đang quét Port và Service bằng Nmap...")

    command = f"nmap -sV -Pn {ip_target}"
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
    except Exception as e:
        print(f"[-] Lỗi hệ thống: {e}")
# Hàm quét SQL Injection bằng SQLMap
def scan_sqli(target):
    print("\n[+] Đang kiểm tra SQL Injection bằng SQLMap...")
    run_command(f"sqlmap -u {target} --dbs --batch")

#-----------------------------------------------#
# 🔥 AI tự động sửa lỗi nếu gặp lỗi khi quét Misconfiguration
def fix_misconfig_scan(target):
    print("\n[AI] Đang thử thay thế `http-config-check.nse` bằng `http-enum.nse`, `http-headers.nse`, `http-vuln*`...")
    run_command(f"nmap --script=http-enum,http-headers,http-vuln* {target}")
# Hàm quét Misconfiguration
def scan_misconfiguration(target):
    print("\n[+] Đang kiểm tra lỗi cấu hình sai...")
    run_command(f"nmap --script=http-config-check.nse {target}", fix_function=lambda: fix_misconfig_scan(target))

#-----------------------------------------------#
# Hàm quét XSS bằng XSStrike
def find_parameters(target):
    """
    Hàm tự động tìm kiếm các URL có tham số trên trang web.
    """
    try:
        # Gửi request đến target
        response = requests.get(target, timeout=10)
        if response.status_code != 200:
            print(f"[-] Không thể kết nối đến {target} (Mã lỗi: {response.status_code})")
            return []
        
        # Tìm tất cả các URL có chứa tham số (ví dụ: ?id=123)
        urls = re.findall(r'href=["\'](https?://.*?\?.*?)["\']', response.text)
        full_urls = [urljoin(target, url) for url in urls]

        return list(set(full_urls))  # Loại bỏ các URL trùng lặp

    except requests.exceptions.RequestException as e:
        print(f"[-] Lỗi khi kết nối đến {target}: {e}")
        return []

def scan_xss(target):
    """
    Hàm quét XSS bằng XSStrike, tự động tìm URL có tham số nếu cần.
    """
    # Chuẩn hóa URL (loại bỏ https:// hoặc http://)
    parsed_url = urlparse(target)
    domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

    print(f"[+] Đang kiểm tra các URL có tham số trên {domain}...")
    urls_with_params = find_parameters(domain)

    if urls_with_params:
        for url in urls_with_params:
            print(f"[+] Đã tìm thấy URL có tham số: {url}")
            print(f"[+] Đang quét XSS bằng XSStrike trên {url}...")
            os.system(f"python3 XSStrike/xsstrike.py -u {url}")
    else:
        print("[-] Không tìm thấy URL nào có tham số để kiểm tra XSS.")
        print("[!] Hãy thử cung cấp một URL cụ thể có tham số.")

#-----------------------------------------------#
# Hàm quét bảo mật web bằng Nikto
def scan_nikto(target):
    print("\n[+] Đang quét bảo mật Webserver bằng Nikto...")
    run_command(f"nikto -h {target}")

#-----------------------------------------------#
# Hàm quét SSRF bằng SSRFmap
def scan_ssrf(target):
    print("\n[+] Đang kiểm tra SSRF bằng SSRFmap...")
    run_command(f"python3 SSRFmap/ssrfmap.py -u {target}")

#-----------------------------------------------#
# Menu chọn kiểu quét
def main():
    print("===================================")
    print("   TOOL PENTEST WEB SERVER AI")
    print("===================================")
    
    target = get_valid_target()  # Bắt buộc nhập URL hợp lệ trước khi chạy tool

    while True:
        print("\nChọn kiểu quét:")
        print("1. Quét Port và Service (Nmap)")
        print("2. Quét XSS (XSStrike)")
        print("3. Quét bảo mật Webserver (Nikto)")
        print("4. Quét SSRF (SSRFmap)")
        print("5. Kiểm tra lỗi cấu hình sai (Misconfiguration)")
        print("6. Quét SQL Injection (SQLMap)")
        print("7. 🔥 Quét tất cả 🔥")
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
        elif choice == "7":
            print("\n🔥 [!] Đang chạy tất cả các bài kiểm tra bảo mật... 🔥")
            scan_nmap(target)
            print("\n✅ Hoàn thành quét Nmap!")
            scan_xss(target)
            print("\n✅ Hoàn thành quét XSS!")
            scan_nikto(target)
            print("\n✅ Hoàn thành quét bảo mật Webserver!")
            scan_ssrf(target)
            print("\n✅ Hoàn thành kiểm tra SSRF!")
            scan_misconfiguration(target)
            print("\n✅ Hoàn thành kiểm tra cấu hình sai!")
            scan_sqli(target)
            print("\n✅ Hoàn thành quét SQL Injection!")
            print("\n🎉 Tất cả các bài quét đã hoàn thành!")
        elif choice == "99":
            print("\n[+] Thoát tool. Hẹn gặp lại!")

if __name__ == "__main__":
    main()