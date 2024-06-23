# subdomain_enum.py
import sublist3r

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []

    def enumerate_subdomains(self):
        self.subdomains = sublist3r.main(self.domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        return self.subdomains
