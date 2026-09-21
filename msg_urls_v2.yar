// v2 - TLD list: https://data.iana.org/TLD/tlds-alpha-by-domain.txt (2026-09-21)
// Domain candidates only: may include parent domains, email domains, file names.
// Bare paths are reduced to their host. No deduplication or UTF-16 decoding.
rule MSG_HTTP_URLs
{
    strings:
        $url = /https?:\/\/[^\x00-\x20\x7f"'<>\\]+/ ascii nocase
    condition:
        $url
}

rule MSG_Domains_000
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--vermgensberatung-pwb|xn--vermgensberater-ctb|xn--clchc0ea0b2g2a9gcd|xn--w4r85el8fhu5dnra|travelersinsurance|xn--5su34j936bgsg|xn--bck1b9a5dre4c|xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgberp4a5d4ar|xn--xkc2dl3a5ee0h|xn--fzys8d69uvgm|xn--mgba7c0bbn0a|xn--mgbcpq6gpa1a|xn--xkc2al3hye2a|americanexpress|kerryproperties|sandvikcoromant|xn--i1b6b1a6a2e|xn--kcrx77d1x4a)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_001
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--lgbbat1ad8j|xn--mgba3a4f16a|xn--mgbc0a9azcg|xn--nqv7fs00ema|americanfamily|weatherchannel|xn--54b7fta0cc|xn--6qq986b3xl|xn--80aqecdr1a|xn--b4w605ferd|xn--fiq228c5hs|xn--h2breg3eve|xn--jlq480n2rg|xn--mgba3a3ejt|xn--mgbaam7a8h|xn--mgbayh7gpa|xn--mgbbh1a71e|xn--mgbca7dzdo|xn--mgbi4ecexp|xn--mgbx4cd0ab)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_002
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--rvc1e0am3e|international|lifeinsurance|xn--cckwcxetd|xn--eckvdtc9d|xn--fpcrj9c3d|xn--fzc2c9e2c|xn--h2brj9c8c|xn--tiq49xqyj|xn--yfro4i67o|xn--ygbi2ammx|construction|lplfinancial|scholarships|versicherung|xn--3e0b707e|xn--45br5cyl|xn--4dbrk0ce|xn--80adxhks|xn--80asehdb)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_003
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--8y0a063a|xn--gckr3f0f|xn--mgb9awbf|xn--mgbab2bd|xn--mgbgu82a|xn--mgbpl2fh|xn--mgbt3dhd|xn--mk1bu44c|xn--ngbc5azd|xn--ngbe9e0a|xn--ogbpf8fl|xn--qcka1pmc|accountants|barclaycard|blackfriday|blockbuster|bridgestone|calvinklein|contractors|creditunion)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_004
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(engineering|enterprises|investments|kerryhotels|lamborghini|motorcycles|olayangroup|photography|playstation|productions|progressive|redumbrella|williamhill|xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--3bst00m|xn--3ds443g|xn--3hcrj9c)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_005
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--42c2d9a|xn--45brj9c|xn--55qw42g|xn--6frz82g|xn--80ao21a|xn--9krt00a|xn--cck2b3b|xn--czr694b|xn--d1acj3b|xn--efvy88h|xn--fct429k|xn--fjq720a|xn--flw351e|xn--g2xx48c|xn--gecrj9c|xn--gk3at1e|xn--h2brj9c|xn--hxt814e|xn--imr513n|xn--j6w193g)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_006
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--jvr189m|xn--kprw13d|xn--kpry57d|xn--mgbbh1a|xn--mgbtx2b|xn--mix891f|xn--nyqy26a|xn--otu796d|xn--pgbs0dh|xn--q9jyb4c|xn--rhqv96g|xn--rovu88b|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--vuq861b|xn--w4rs40l|xn--xhq521b|xn--zfr164b|accountant)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_007
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(apartments|associates|basketball|bnpparibas|boehringer|capitalone|consulting|creditcard|cuisinella|eurovision|extraspace|foundation|healthcare|immobilien|industries|management|mitsubishi|nextdirect|properties|protection)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_008
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(prudential|realestate|republican|restaurant|schaeffler|tatamotors|technology|university|vlaanderen|xn--30rr7y|xn--3pxu8k|xn--45q11c|xn--4gbrim|xn--55qx5d|xn--5tzm5g|xn--80aswg|xn--90a3ac|xn--9dbq2a|xn--9et52u|xn--c2br7g)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_009
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--cg4bki|xn--czrs0t|xn--czru2d|xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--io0a7i|xn--kput3i|xn--mxtq1m|xn--o3cw4h|xn--pssy2u|xn--q7ce6a|xn--unup4y|xn--wgbh1c|xn--wgbl6a|xn--y9a3aq|accenture|allfinanz|amsterdam|analytics)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_010
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(aquarelle|barcelona|bloomberg|christmas|community|directory|education|equipment|fairwinds|financial|firestone|fresenius|furniture|goldpoint|hisamitsu|homedepot|homegoods|homesense|institute|insurance)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_011
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(kuokgroup|landrover|lifestyle|marketing|marshalls|melbourne|microsoft|panasonic|richardli|shangrila|solutions|statebank|statefarm|stockholm|travelers|vacations|xn--90ais|xn--c1avg|xn--d1alf|xn--e1a4c)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_012
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(xn--fhbei|xn--j1aef|xn--j1amh|xn--l1acc|xn--ngbrx|xn--nqv7f|xn--p1acf|xn--qxa6a|xn--tckwe|xn--vhquv|yodobashi|abudhabi|airforce|allstate|attorney|barclays|barefoot|bargains|baseball|boutique)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_013
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(bradesco|broadway|brussels|builders|business|capetown|catering|catholic|cipriani|cleaning|clinique|clothing|commbank|computer|delivery|deloitte|democrat|diamonds|discount|discover)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_014
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(download|engineer|ericsson|exchange|feedback|fidelity|firmdale|football|frontier|goodyear|grainger|graphics|hdfcbank|helsinki|holdings|hospital|infiniti|ipiranga|istanbul|jpmorgan)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_015
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(lighting|lundbeck|marriott|mckinsey|memorial|merckmsd|mortgage|observer|partners|pharmacy|pictures|plumbing|property|reliance|saarland|samsclub|security|services|shopping|softbank)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_016
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(software|stcgroup|supplies|training|vanguard|ventures|verisign|woodside|xn--90ae|xn--node|xn--p1ai|xn--qxam|yokohama|abogado|academy|agakhan|alibaba|android|athleta|auction)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_017
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(audible|auspost|banamex|bauhaus|bestbuy|booking|brother|capital|caravan|careers|channel|charity|chintai|citadel|clubmed|college|cologne|company|compare|contact)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_018
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(cooking|corsica|country|coupons|courses|cricket|cruises|dentist|digital|domains|exposed|express|farmers|fashion|ferrari|ferrero|finance|fishing|fitness|flights)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_019
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(florist|flowers|forsale|frogans|fujitsu|gallery|genting|godaddy|grocery|guitars|hamburg|hangout|hitachi|holiday|hosting|hotmail|hyundai|ismaili|jewelry|juniper)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_020
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(kitchen|komatsu|lacaixa|lanxess|lasalle|latrobe|leclerc|limited|lincoln|markets|monster|netbank|netflix|network|neustar|okinawa|organic|origins|philips|pioneer)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_021
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(politie|realtor|recipes|rentals|reviews|rexroth|samsung|sandvik|schmidt|schwarz|science|shiksha|singles|staples|storage|support|surgery|systems|temasek|theater)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_022
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(theatre|tickets|toshiba|trading|walmart|wanggou|watches|weather|website|wedding|whoswho|windows|winners|yamaxun|youtube|zuerich|abbott|abbvie|africa|agency)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_023
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(airbus|airtel|alipay|alsace|alstom|amazon|anquan|aramco|author|bayern|beauty|berlin|bharti|bostik|boston|broker|camera|career|casino|center)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_024
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(chanel|chrome|church|circle|claims|clinic|coffee|comsec|condos|coupon|credit|cruise|dating|datsun|dealer|degree|dental|design|direct|doctor)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_025
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(dupont|durban|emerck|energy|estate|events|expert|family|flickr|futbol|gallup|garden|george|giving|global|google|gratis|health|hermes|hiphop)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_026
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(hockey|hotels|hughes|imamat|insure|intuit|jaguar|joburg|juegos|kaufen|kindle|kosher|latino|lawyer|lefrak|living|locker|london|luxury|madrid)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_027
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(maison|makeup|market|mattel|mobile|monash|mormon|moscow|museum|nagoya|nissan|nissay|norton|nowruz|office|olayan|online|oracle|orange|otsuka)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_028
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(pfizer|photos|physio|pictet|quebec|racing|realty|reisen|repair|report|review|rogers|ryukyu|safety|sakura|sanofi|school|schule|search|secure)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_029
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(select|shouji|soccer|social|stream|studio|supply|suzuki|swatch|sydney|taipei|taobao|target|tattoo|tennis|tienda|tjmaxx|tkmaxx|toyota|travel)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_030
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(unicom|viajes|viking|villas|virgin|vision|voting|voyage|walter|webcam|xihuan|yachts|yandex|zappos|actor|adult|aetna|amfam|amica|apple)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_031
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(archi|audio|autos|azure|baidu|beats|bible|bingo|black|boats|bosch|build|canon|cards|chase|cheap|cisco|citic|click|cloud)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_032
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(coach|codes|crown|cymru|dance|deals|delta|drive|dubai|earth|edeka|email|epson|faith|fedex|final|forex|forum|gallo|games)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_033
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(gifts|gives|glass|globo|gmail|green|gripe|group|gucci|guide|homes|honda|horse|house|hyatt|ikano|irish|jetzt|koeln|kyoto)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_034
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(lamer|lease|legal|lexus|lilly|loans|locus|lotte|lotto|mango|media|merck|miami|money|movie|music|nexus|nikon|ninja|nokia)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_035
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(nowtv|omega|osaka|paris|parts|party|phone|photo|pizza|place|poker|praxi|press|prime|promo|quest|radio|rehab|reise|ricoh)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_036
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(rocks|rodeo|rugby|salon|sener|seven|sharp|shell|shoes|skype|sling|smart|smile|solar|space|sport|stada|store|study|style)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_037
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(sucks|swiss|tatar|tires|tirol|tmall|today|tokyo|tools|toray|total|tours|trade|trust|tunes|tushu|ubank|vegas|video|vodka)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_038
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(volvo|wales|watch|weber|weibo|works|world|xerox|yahoo|aarp|able|aero|akdn|ally|amex|arab|army|arpa|arte|asda)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_039
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(asia|audi|auto|baby|band|bank|bbva|beer|best|bike|bing|blog|blue|bofa|bond|book|buzz|cafe|call|camp)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_040
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(care|cars|casa|case|cash|cbre|cern|chat|citi|city|club|cool|coop|cyou|data|date|dclk|deal|dell|desi)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_041
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(diet|dish|docs|dvag|erni|fage|fail|fans|farm|fast|fido|film|fire|fish|flir|food|ford|free|fund|game)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_042
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(gbiz|gent|ggee|gift|gmbh|gold|golf|goog|guge|guru|hair|haus|hdfc|help|here|host|hsbc|icbc|ieee|imdb)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_043
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(immo|info|itau|java|jeep|jobs|jprs|kddi|kids|kiwi|kpmg|kred|land|lego|lgbt|lidl|life|like|limo|link)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_044
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(live|loan|love|ltda|luxe|maif|meet|meme|menu|mini|mint|mobi|moda|moto|name|navy|news|next|nico|nike)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_045
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(ollo|open|page|pars|pccw|pics|ping|pink|play|plus|pohl|porn|post|prod|prof|qpon|read|reit|rent|rest)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_046
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(rich|room|rsvp|ruhr|safe|sale|sarl|save|saxo|scot|seat|seek|sexy|shia|shop|show|silk|sina|site|skin)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_047
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(sncf|sohu|song|sony|spot|star|surf|talk|taxi|team|tech|teva|tiaa|tips|town|toys|tube|vana|visa|viva)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_048
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(vivo|vote|voto|wang|weir|wien|wiki|wine|work|xbox|yoga|zara|zero|zone|aaa|abb|abc|aco|ads|aeg)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_049
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(afl|aig|anz|aol|app|art|aws|axa|bar|bbc|bbt|bcg|bcn|bet|bid|bio|biz|bms|bmw|bom)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_050
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(boo|bot|box|buy|bzh|cab|cal|cam|car|cat|cba|cbn|ceo|cfa|cfd|com|cpa|crs|dad|day)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_051
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(dds|dev|dhl|diy|dnp|dog|dot|dtv|dvr|eat|eco|edu|esq|eus|fan|fit|fly|foo|fox|frl)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_052
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(ftr|fun|fyi|gal|gap|gay|gdn|gea|gle|gmo|gmx|gop|got|gov|hbo|hiv|hkt|hot|how|ibm)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_053
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(ice|icu|ifm|inc|ing|ink|int|ist|itv|jcb|jio|jll|jmp|jnj|jot|joy|kfh|kia|kim|kpn)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_054
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(krd|lat|law|lds|llc|llp|lol|lpl|ltd|man|map|mba|med|men|mil|mit|mlb|mls|mma|moe)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_055
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(moi|mom|mov|msd|mtn|mtr|nab|nba|nec|net|new|nfl|ngo|nhk|now|nra|nrw|ntt|nyc|obi)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_056
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(one|ong|onl|ooo|org|ott|ovh|pay|pet|phd|pid|pin|pnc|pro|pru|pub|pwc|red|ren|ril)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_057
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(rio|rip|run|rwe|sap|sas|sbi|sbs|scb|sew|sex|sfr|ski|sky|soy|spa|srl|stc|tab|tax)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_058
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(tci|tdk|tel|thd|tjx|top|trv|tui|tvs|ubs|uno|uol|ups|vet|vig|vin|vip|web|wed|win)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_059
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(wme|wow|wtc|wtf|xin|xxx|xyz|you|yun|zip|ac|ad|ae|af|ag|ai|al|am|ao|aq)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_060
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_061
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_062
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_063
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_064
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_065
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_066
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_067
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_068
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_069
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_070
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug)/ ascii nocase fullword
    condition:
        $domain
}

rule MSG_Domains_071
{
    strings:
        $domain = /[a-z0-9][a-z0-9.-]*\.(uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)/ ascii nocase fullword
    condition:
        $domain
}
