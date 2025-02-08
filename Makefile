rebuild: clean dnsres
clean:
	rm -f dnsres
dnsres: 
	gcc dnsres.c -o dnsres
.PHONY: clean