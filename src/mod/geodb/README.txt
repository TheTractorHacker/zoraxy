The data source for geoip is licensed under CC0
If you want to build your own version of geodb with updated whitelist,
you can go to this repo and get the "GeoFeed + Whois + ASN" version of 
both the IPV4 and IPV6 mapping (the one without -num)

https://github.com/sapics/ip-location-db/tree/main/geolite2-country

And rename it to "gepipv4.csv" and "gepipv6.csv"

Known corrections (overrides.go)
--------------------------------
The source data has some wrong rows (for example very wide gap-filling AU rows in the IPv6 table that
made Malaysian prefixes resolve to AU, upstream #1334). overrides.go pins the verified ranges on top of
the CSV, whether it is the embedded or a downloaded one. After replacing geoipv4.csv / geoipv6.csv, check
each override against the new data and remove the ones that are no longer needed.
