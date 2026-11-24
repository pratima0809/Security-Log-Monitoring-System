import ipaddress


def analyze_ip(ip):

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            category = "LOOPBACK"

        elif address.is_private:
            category = "PRIVATE / INTERNAL"

        elif address.is_global:
            category = "PUBLIC / EXTERNAL"

        else:
            category = "RESERVED / SPECIAL"

        return {
            "ip": ip,
            "category": category
        }

    except ValueError:
        return {
            "ip": ip,
            "category": "INVALID IP"
        }
