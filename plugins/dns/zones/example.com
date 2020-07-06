$TTL 36000
example.com. IN      SOA     ns1.example.com. hostmaster.example.com. (
               2005081201      ; serial
               28800   ; refresh (8 hours)
               1800    ; retry (30 mins)
               2592000 ; expire (30 days)
               86400 ) ; minimum (1 day)

example.com.     86400   NS      ns1.example.com.
example.com.     86400   NS      ns2.example.com.
example.com.     86400   MX 10   mail1.n2.example.com.
example.com.     86400   MX 20   mail2.example.com.
example.com.     86400   A       192.168.10.10
example.com.     86400   A       192.168.10.11
example.com.     86400   TXT     "v=spf1 a:mail.example.com -all"

ns1.example.com.        86400   A       192.168.1.10
ns1.example.com.        86400   A       192.168.1.11
ns2.example.com.        86400   A       192.168.1.20
mail.example.com.       86400   A       192.168.2.10
mail2.example.com.      86400   A       192.168.2.20
www2.example.com.       86400   A       192.168.10.20

www.example.com.        86400 CNAME     example.com.
ftp.example.com.        86400 CNAME     example.com.
webmail.example.com.    86400 CNAME     example.com.