The following is a library of strategies, the countries they work in, and their average success rates in those countries. See the readme or our paper for an explanation of the strategy DNA format.  


| Strategy 	| China 	| Kazakhstan 	| India 	|
|------------------------------------------------------------------------------------------------------	|-------	|------------	|-------	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-\|` 	| 98% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{IP:ttl:replace:10},),)-\|` 	| 98% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:ack:corrupt},),)-\|` 	| 94% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:options-wscale:corrupt}(tamper{TCP:dataofs:replace:8},),)-\|` 	| 98% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:chksum:corrupt},),)-\|` 	| 80% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{IP:ttl:replace:8},),)-\|` 	| 98% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:load:corrupt}(tamper{TCP:ack:corrupt},),)-\|` 	| 87% 	| 100% 	| 0% 	|
| `[TCP:flags:S]-duplicate(,tamper{TCP:load:corrupt})-\|` 	| 3% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-duplicate(tamper{IP:len:replace:64},)-\|` 	| 3% 	| 0% 	| 100% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-\|` 	| 95% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:R}(tamper{IP:ttl:replace:10},))-\|` 	| 87% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-\|` 	| 86% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{TCP:chksum:corrupt},))-\|` 	| 80% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:RA}(tamper{IP:ttl:replace:10},))-\|` 	| 94% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:options-md5header:corrupt}(tamper{TCP:flags:replace:R},))-\|` 	| 94% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUEN}(tamper{TCP:chksum:corrupt},))-\|` 	| 89% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FREACN}(tamper{IP:ttl:replace:10},))-\|` 	| 96% 	| 0% 	| 0% 	|
| `[TCP:flags:A]-duplicate(,tamper{TCP:flags:replace:FRAPUN}(tamper{TCP:options-md5header:corrupt},))-\|` 	| 94% 	| 0% 	| 0% 	|
| `[TCP:flags:PA]-fragment{tcp:8:False}-\| [TCP:flags:A]-tamper{TCP:seq:corrupt}-\|` 	| 94% 	| 100% 	| 100% 	|
| `[TCP:flags:PA]-fragment{tcp:8:True}(,fragment{tcp:4:True})-\|` 	| 98% 	| 100% 	| 100% 	|
| `[TCP:flags:PA]-fragment{tcp:-1:True}-\| `	| 3% 	| 100% 	| 100% 	|
| `[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:F}(tamper{IP:len:replace:78},),)-\| `	| 53% 	| 0% 	| 100% 	|
| `[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:SA},)-\|` 	| 3% 	| 100% 	| 0% 	|
| `[TCP:flags:PA]-tamper{TCP:options-uto:corrupt}-\| `	| 3% 	| 0% 	| 100% 	|
