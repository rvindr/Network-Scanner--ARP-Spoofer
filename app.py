from flask import Flask, render_template, request,url_for
import scapy.all as scapy
import ipapi

app = Flask(__name__)

@app.route('/')
def main_app():  
    return render_template("index.html")
@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/ip-lookup', methods=['GET', 'POST'])
def ipLookup():
    search = request.form.get('ip_add_value')
    data = ipapi.location(search, output='json')
    return render_template('ip.html', data=data)


@app.route('/postip', methods=["POST", "GET"])
def get_ip():
    user_ip = request.form.to_dict()
    mod_ip= user_ip["ip_add"]+"/24"
    show='true'
    scan_result = Scanner.scan(mod_ip)
    return render_template('index.html', scan_result=scan_result,show=show)


class Scanner:
    def scan(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []

        for element in answered_list:
            clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(clients_dict)
        print(clients_list)
        return clients_list




if __name__ == '__main__':
    app.run(debug=True, port=5000)
