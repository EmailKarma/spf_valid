import dns.resolver
import ipaddress

validation_path = []
matched_mechanism = None
visited_domains = set()


def fetch_spf_record(domain):
    print(f"Fetching SPF record for domain: {domain}")

    try:
        answers = dns.resolver.resolve(domain, "TXT")

        for rdata in answers:
            txt_record = b"".join(rdata.strings).decode("utf-8").strip()

            if txt_record.startswith("v=spf1"):
                print(f"Found SPF record: {txt_record}")
                return txt_record

        print("No SPF record found.")
        return None

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ) as e:
        print(f"Error fetching SPF record: {e}")
        return None


def parse_spf_record(spf_record):
    spf_directives = spf_record.split()[1:]
    print(f"Parsed SPF directives: {spf_directives}")
    return spf_directives


def reverse_ipv6(ip):
    expanded = ipaddress.ip_address(ip).exploded.replace(":", "")
    return ".".join(reversed(expanded))


def expand_spf_macros(ip, macro, domain):
    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.version == 4:
        ip_reverse = ".".join(reversed(ip.split(".")))
        ip_version = "in-addr"
    else:
        ip_reverse = reverse_ipv6(ip)
        ip_version = "ip6"

    expanded_macro = macro
    expanded_macro = expanded_macro.replace("%{ir}", ip_reverse)
    expanded_macro = expanded_macro.replace("%{v}", ip_version)
    expanded_macro = expanded_macro.replace("%{d}", domain)
    expanded_macro = expanded_macro.replace("%{i}", ip)

    print(f"Expanded macro: {expanded_macro}")
    return expanded_macro


def resolve_addresses(domain, ip_version):
    record_type = "A" if ip_version == 4 else "AAAA"

    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [ipaddress.ip_address(answer.to_text()) for answer in answers]

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ) as e:
        print(f"No {record_type} record found for {domain}: {e}")
        return []


def check_dns_record(expanded_domain, record_type):
    try:
        records = dns.resolver.resolve(expanded_domain, record_type)

        if records:
            print(f"Domain {expanded_domain} has {record_type} record.")
            return True

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ) as e:
        print(f"No {record_type} record found for domain {expanded_domain}: {e}")

    return False


def is_ip_in_cidr(ip, cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in network
    except ValueError as e:
        print(f"Invalid CIDR skipped: {cidr} ({e})")
        return False


def strip_qualifier(directive):
    if directive[:1] in ["+", "-", "~", "?"]:
        return directive[1:]
    return directive


def split_domain_and_cidr(value, default_domain, ip_version):
    """
    Parse SPF a/mx values such as:
      a
      a:mail.example.com
      a/24
      a:mail.example.com/24
      a//64
      a:mail.example.com/24//64

    Returns the target domain and the applicable prefix length.
    """
    target_domain = value or default_domain
    ipv4_prefix = 32
    ipv6_prefix = 128

    if "//" in target_domain:
        left, ipv6_part = target_domain.split("//", 1)
        target_domain = left
        if ipv6_part:
            ipv6_prefix = int(ipv6_part)

    if "/" in target_domain:
        target_domain, ipv4_part = target_domain.rsplit("/", 1)
        if ipv4_part:
            ipv4_prefix = int(ipv4_part)

    if not target_domain:
        target_domain = default_domain

    prefix = ipv4_prefix if ip_version == 4 else ipv6_prefix
    return target_domain, prefix


def address_matches(ip, candidate_address, prefix_length):
    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.version != candidate_address.version:
        return False

    network = ipaddress.ip_network(
        f"{candidate_address}/{prefix_length}",
        strict=False,
    )
    return ip_obj in network


def check_a_mechanism(ip, directive, current_domain):
    value = directive[1:] if directive.startswith("a") else ""
    if value.startswith(":"):
        value = value[1:]

    try:
        target_domain, prefix_length = split_domain_and_cidr(
            value,
            current_domain,
            ipaddress.ip_address(ip).version,
        )
    except ValueError as e:
        print(f"Invalid a mechanism skipped: {directive} ({e})")
        return False

    validation_path.append(f"a:{target_domain}/{prefix_length}")
    print(f"Checking A/AAAA records for: {target_domain}")

    for address in resolve_addresses(target_domain, ipaddress.ip_address(ip).version):
        if address_matches(ip, address, prefix_length):
            return True

    return False


def check_mx_mechanism(ip, directive, current_domain):
    value = directive[2:] if directive.startswith("mx") else ""
    if value.startswith(":"):
        value = value[1:]

    try:
        target_domain, prefix_length = split_domain_and_cidr(
            value,
            current_domain,
            ipaddress.ip_address(ip).version,
        )
    except ValueError as e:
        print(f"Invalid mx mechanism skipped: {directive} ({e})")
        return False

    validation_path.append(f"mx:{target_domain}/{prefix_length}")
    print(f"Checking MX hosts for: {target_domain}")

    try:
        mx_answers = dns.resolver.resolve(target_domain, "MX")
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.Timeout,
        dns.resolver.NoNameservers,
    ) as e:
        print(f"No MX records found for {target_domain}: {e}")
        return False

    for mx_answer in mx_answers:
        mx_host = str(mx_answer.exchange).rstrip(".")
        print(f"Checking MX host: {mx_host}")

        for address in resolve_addresses(mx_host, ipaddress.ip_address(ip).version):
            if address_matches(ip, address, prefix_length):
                return True

    return False


def check_ip_in_spf(ip, spf_directives, domain):
    global matched_mechanism

    ip = ip.strip()
    print(f"Checking IP: {ip}")

    domain_key = domain.lower().rstrip(".")
    if domain_key in visited_domains:
        print(f"Loop detected while checking {domain}.")
        return False

    visited_domains.add(domain_key)
    redirect_domain = None

    try:
        for raw_directive in spf_directives:
            print(f"Checking directive: {raw_directive}")

            directive = strip_qualifier(raw_directive)

            if directive == "all":
                print(f"Ignoring {raw_directive} directive.")
                continue

            if directive.startswith("redirect="):
                redirect_domain = expand_spf_macros(
                    ip,
                    directive.split("=", 1)[1],
                    domain,
                )
                continue

            if directive.startswith("include:"):
                included_domain = expand_spf_macros(
                    ip,
                    directive.split(":", 1)[1],
                    domain,
                )
                validation_path.append(f"include:{included_domain}")

                print(f"Checking if SPF record exists for domain: {included_domain}")
                included_spf_record = fetch_spf_record(included_domain)

                if included_spf_record:
                    included_spf_directives = parse_spf_record(included_spf_record)

                    if check_ip_in_spf(ip, included_spf_directives, included_domain):
                        matched_mechanism = matched_mechanism or f"include:{included_domain}"
                        return True

            elif directive.startswith("exists:"):
                expanded_domain = expand_spf_macros(
                    ip,
                    directive.split(":", 1)[1],
                    domain,
                )
                validation_path.append(f"exists:{expanded_domain}")

                print(f"Checking if A record exists for domain: {expanded_domain}")

                if check_dns_record(expanded_domain, "A"):
                    matched_mechanism = f"exists:{expanded_domain}"
                    return True

            elif directive == "a" or directive.startswith("a:") or directive.startswith("a/"):
                if check_a_mechanism(ip, directive, domain):
                    matched_mechanism = directive
                    return True

            elif directive == "mx" or directive.startswith("mx:") or directive.startswith("mx/"):
                if check_mx_mechanism(ip, directive, domain):
                    matched_mechanism = directive
                    return True

            elif directive.startswith("ip4:") or directive.startswith("ip6:"):
                cidr = directive.split(":", 1)[1]
                validation_path.append(directive)

                if is_ip_in_cidr(ip, cidr):
                    matched_mechanism = directive
                    return True

        if redirect_domain:
            validation_path.append(f"redirect={redirect_domain}")
            print(f"Following redirect to: {redirect_domain}")

            redirect_spf_record = fetch_spf_record(redirect_domain)

            if redirect_spf_record:
                redirect_directives = parse_spf_record(redirect_spf_record)

                if check_ip_in_spf(ip, redirect_directives, redirect_domain):
                    matched_mechanism = matched_mechanism or f"redirect={redirect_domain}"
                    return True

        print(f"IP {ip} is not valid according to this SPF record.")
        return False

    finally:
        visited_domains.discard(domain_key)


def print_results_summary(ip, domain, result):
    print("\n--------------------------------------------------")
    print("Results Summary")
    print("--------------------------------------------------")
    print(f"Domain: {domain}")
    print(f"IP: {ip}")

    if result:
        print("\nResult: VALID")
        print(f"Record valid under: {matched_mechanism}")
    else:
        print("\nResult: NOT VALID")
        print(f"Record not valid for: {domain}")

    if validation_path:
        print("\nValidation Path:")
        for item in validation_path:
            print(f"  - {item}")


def main():
    global matched_mechanism

    validation_path.clear()
    visited_domains.clear()
    matched_mechanism = None

    ip = input("Enter the IP address: ").strip()
    domain = input("Enter the domain: ").strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"Invalid IP address: {ip}")
        return

    spf_record = fetch_spf_record(domain)

    if spf_record:
        print(f"SPF Record: {spf_record}")
        spf_directives = parse_spf_record(spf_record)
        result = check_ip_in_spf(ip, spf_directives, domain)
    else:
        print(f"No SPF record found for {domain}.")
        result = False

    print_results_summary(ip, domain, result)


if __name__ == "__main__":
    main()
