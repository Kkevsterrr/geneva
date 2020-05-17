$TTL 36000
example2.com. IN      SOA     ns1.example2.com. hostmaster.example2.com. (
               2005081201      ; serial
               28800   ; refresh (8 hours)
               1800    ; retry (30 mins)
               2592000 ; expire (30 days)
               86400 ) ; minimum (1 day)

example2.com.     86400   NS      ns1.example2.com.
example2.com.     86400   NS      ns2.example2.com.
example2.com.     86400   MX 10   mail1.n2.example2.com.
example2.com.     86400   MX 20   mail2.example2.com.
example2.com.     86400   A       192.168.111.10
example2.com.     86400   A       192.168.111.11
example2.com.     86400   TXT     "v=spf1 a:mail.example2.com -all"

ns1.example2.com.        86400   A       192.168.110.10
ns1.example2.com.        86400   A       192.168.110.11
ns2.example2.com.        86400   A       192.168.110.20
mail.example2.com.       86400   A       192.168.120.10
mail2.example2.com.      86400   A       192.168.120.20
www2.example2.com.       86400   A       192.168.100.20

www.example2.com.        86400 CNAME     example2.com.
ftp.example2.com.        86400 CNAME     example2.com.
webmail.example2.com.    86400 CNAME     example2.com.