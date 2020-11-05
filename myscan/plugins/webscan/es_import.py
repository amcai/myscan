# !/usr/bin/env python3
# @Time    : 2020/8/31
# @Author  : caicai
# @File    : es_import.py
from elasticsearch import helpers
from myscan.lib.core.data import others
from myscan.lib.core.data import logger
from myscan.lib.core.common import getmd5, getredis
import re
from myscan.config import db_set
import mmh3, base64
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from myscan.lib.core.threads import mythread
import traceback
from myscan.lib.core.dns import find_domain_ip


class POC():
    def __init__(self, dictdata):
        self.dictdata = dictdata
        self.dict_host_ip = {}
        self.hosts = set()
        self.red = getredis()

    def verify(self):
        dictdata = self.dictdata
        # 把请求体和响应体 base64解码，便于搜索
        request_raw = base64.b64decode(self.dictdata.get("request").get("raw").encode("utf8"))
        response_raw = base64.b64decode(self.dictdata.get("response").get("raw").encode("utf8"))
        dictdata["request"]["raw"] = request_raw.decode("utf-8", errors="ignore")
        dictdata["response"]["raw"] = response_raw.decode("utf-8", errors="ignore")
        if "others" in dictdata.keys():
            del dictdata["others"]
        if "filter" in dictdata.keys():
            del dictdata["filter"]
        dictdata["source"] = "burp"
        dictdata["url"]["ip"] = self.getaddr(dictdata.get("url").get("host"))
        dictdata["url"]["pathroot"] = "{protocol}://{host}:{port}/".format(**dictdata.get("url"))
        if dictdata["url"]["extension"] == "ico":
            body = response_raw[int(dictdata.get("response").get("bodyoffset")):]
            dictdata["url"]["icon_hash"] = str(mmh3.hash(base64.b64encode(body)))
        actions = []
        action = {
            "_index": "httpinfo",
            "_id": self.http_md5(dictdata),
            "_source": dictdata
        }
        actions.append(action)

        # get url from html

        urls_from_html = self.get_html_url(dictdata["url"]["url"],
                                           response_raw[int(dictdata.get("response").get("bodyoffset")):].decode(
                                               "utf-8",
                                               "ignore"),
                                           dictdata["response"]["mime_inferred"])
        logger.debug("urls_from_html    total:{}".format(len(urls_from_html)))
        if urls_from_html:
            mythread(self.getaddr, self.hosts, 50)
            for url_data in urls_from_html:
                url_data["ip"] = self.dict_host_ip[url_data["host"]]
                action_ = {
                    "_index": "httpinfo",
                    "_id": getmd5("{ip}{pathroot}{path}".format(**url_data)),
                    "_source": {"url": url_data,
                                "source": "html",
                                "ts": dictdata["ts"]}
                }
                actions.append(action_)

        try:
            helpers.bulk(others.es_conn, actions)
            logger.debug("es insert {} lines".format(len(actions)))
        except Exception as ex:
            logger.warning("Plugin {} get error:{}".format(__name__, ex))
            traceback.print_exc()

    def getaddr(self, domain):
        domain_ = find_domain_ip(domain)
        ipmsg = domain_.find_ip()
        self.dict_host_ip[domain] = ipmsg
        return ipmsg

    def format_url(self, url):
        '''
        will like:
         "path": "/_nlpcn/sql/explain",
          "protocol": "http",
          "extension": "",
          "path_folder": "http://192.168.0.110:9200/_nlpcn/sql/",
          "port": 9200,
          "host": "192.168.0.110",
          "url": "http://192.168.0.110:9200/_nlpcn/sql/explain",
          "ip": "192.168.0.110",
          "pathroot": "http://192.168.0.110:9200/"
        '''
        url_info = urlparse(url)
        path = url_info.path if url_info.path else "/"
        extension_tmp = path.split("#")[0].split(";")[0].split(".")
        extension = ""
        if len(extension_tmp) >= 2:
            extension = extension_tmp[-1]
        host = url_info.netloc.split(":")[0]
        port = 0
        if ":" in url_info.netloc:
            try:
                port = int(url_info.netloc.split(":")[-1])
            except:
                pass
        else:
            port = 443 if url_info.scheme == "https" else 80
        info = {
            "path": path,
            "protocol": url_info.scheme,
            "extension": extension,
            "path_folder": "{}://{}:{}{}".format(url_info.scheme, host, port, "/".join(path.split("/")[:-1]) + "/"),
            "port": port,
            "host": host,
            "url": url,
            # "ip": self.getaddr(host),
            "pathroot": "{}://{}:{}/".format(url_info.scheme, host, port)

        }
        self.hosts.add(host)
        return info

    def get_html_url(self, from_url, response, response_mime):
        if response_mime.lower() not in ["html", "script", "xml", "json", ""]:
            return []
        links = []
        if "html" in response_mime.lower():
            html = BeautifulSoup(response, "html.parser")
            # get from html
            for html_a in html.findAll("a"):
                src = html_a.get("href")
                if src == "" or src == None: continue
                link = self.process_url(from_url, src)
                if link not in links:
                    links.append(link)
            # get from script
            html_scripts = html.findAll("script")
            for html_script in html_scripts:
                script_src = html_script.get("src")
                if script_src == "" or script_src == None: continue
                purl = self.process_url(from_url, script_src)
                links.append(purl)
        # get from re
        domain_suf = '(aaa|aarp|abarth|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|academy|accenture|accountant|accountants|aco|active|actor|ad|adac|ads|adult|ae|aeg|aero|aetna|af|afamilycompany|afl|africa|ag|agakhan|agency|ai|aig|aigo|airbus|airforce|airtel|akdn|al|alfaromeo|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|americanexpress|americanfamily|amex|amfam|amica|amsterdam|an|analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|autos|avianca|aw|aws|ax|axa|az|azure|baby|baidu|banamex|bananarepublic|band|bank|bar|barcelona|barclaycard|barclays|barefoot|bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|be|beats|beauty|beer|bentley|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|bible|bid|bike|bing|bingo|bio|biz|bj|bl|black|blackfriday|blanco|blockbuster|blog|bloomberg|blue|bm|bms|bmw|bn|bnl|bnpparibas|bo|boats|boehringer|bofa|bom|bond|boo|book|booking|boots|bosch|bostik|boston|bot|boutique|box|bq|br|bradesco|bridgestone|broadway|broker|brother|brussels|bs|bt|budapest|bugatti|build|builders|business|buy|buzz|bv|bw|by|bz|bzh|cab|cafe|cal|call|calvinklein|cam|camera|camp|cancerresearch|canon|capetown|capital|capitalone|car|caravan|cards|care|career|careers|cars|cartier|casa|case|caseih|cash|casino|cat|catering|catholic|cba|cbn|cbre|cbs|cc|cd|ceb|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|chase|chat|cheap|chintai|chloe|christmas|chrome|chrysler|church|ci|cipriani|circle|cisco|citadel|citi|citic|city|cityeats|ck|cl|claims|cleaning|click|clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|college|cologne|com|comcast|commbank|community|company|compare|computer|comsec|condos|construction|consulting|contact|contractors|cooking|cookingchannel|cool|coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|creditunion|cricket|crown|crs|cruise|cruises|csc|cu|cuisinella|cv|cw|cx|cy|cymru|cyou|cz|dad|dance|data|date|dating|datsun|day|dclk|dds|de|deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dodge|dog|doha|domains|doosan|dot|download|drive|dtv|dubai|duck|dunlop|duns|dupont|durban|dvag|dvr|dz|eat|ec|eco|edeka|edu|education|ee|eg|eh|email|emerck|energy|engineer|engineering|enterprises|epost|epson|equipment|er|ericsson|erni|es|esq|estate|esurance|et|etisalat|eu|eurovision|eus|events|everbank|exchange|expert|exposed|express|extraspace|fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|feedback|ferrari|ferrero|fi|fiat|fidelity|fido|film|final|finance|financial|fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|flir|florist|flowers|flsmidth|fly|fm|fo|foo|food|foodnetwork|football|ford|forex|forsale|forum|foundation|fox|fr|free|fresenius|frl|frogans|frontdoor|frontier|ftr|fujitsu|fujixerox|fun|fund|furniture|futbol|fyi|gal|gallery|gallo|gallup|game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glade|glass|gle|global|globo|gm|gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodhands|goodyear|goog|google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|grocery|group|gs|gt|gu|guardian|gucci|guge|guide|guitars|guru|gw|gy|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|helsinki|here|hermes|hgtv|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|holdings|holiday|homedepot|homegoods|homes|homesense|honda|honeywell|horse|hospital|host|hosting|hot|hoteles|hotels|hotmail|house|how|hr|hsbc|ht|htc|hu|hughes|hyatt|hyundai|icbc|ice|icu|id|ie|ieee|ifm|iinet|ikano|il|im|imamat|imdb|immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|insurance|insure|int|intel|international|intuit|investments|io|ipiranga|iq|ir|irish|is|iselect|ismaili|ist|istanbul|it|itau|itv|iveco|iwc|java|jcb|jcp|je|jeep|jetzt|jewelry|jio|jlc|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|juegos|juniper|kddi|ke|kerryhotels|kerrylogistics|kerryproperties|kfh|kg|kh|ki|kia|kim|kinder|kindle|kitchen|kiwi|km|kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|kz|lacaixa|ladbrokes|lamborghini|lamer|lancaster|lancia|lancome|land|landrover|lanxess|lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|legal|lego|lexus|lgbt|li|liaison|lidl|life|lifeinsurance|lifestyle|lighting|like|lilly|limited|limo|lincoln|linde|link|lipsy|live|living|lixil|lk|llc|llp|loan|loans|locker|locus|loft|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|lt|ltd|ltda|lu|lundbeck|lupin|luxe|luxury|lv|ly|macys|madrid|maif|maison|makeup|man|management|mango|map|market|marketing|markets|marriott|marshalls|maserati|mattel|mba|mc|mcd|mcdonalds|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|menu|meo|merckmsd|metlife|mf|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|mlb|mls|mm|mma|mn|mo|mobi|mobile|mobily|moda|moe|moi|mom|monash|money|monster|montblanc|mopar|mormon|mortgage|moscow|moto|motorcycles|mov|movie|movistar|mp|mq|mr|ms|msd|mt|mtn|mtpc|mtr|mu|museum|mutual|mutuelle|mv|mw|mx|my|mz|nab|nadex|nagoya|name|nationwide|natura|navy|nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|newholland|news|next|nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|nissay|nl|no|nokia|northwesternmutual|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|observer|off|office|okinawa|olayan|olayangroup|oldnavy|ollo|om|omega|one|ong|onl|online|onyourside|ooo|open|oracle|orange|org|organic|orientexpress|origins|osaka|otsuka|ott|ovh|page|pamperedchef|panasonic|panerai|paris|pars|partners|parts|party|passagens|pay|pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|photography|photos|physio|piaget|pics|pictet|pictures|pid|pin|ping|pink|pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|poker|politie|porn|post|pr|pramerica|praxi|press|prime|pro|prod|productions|prof|progressive|promo|properties|property|protection|pru|prudential|ps|pt|pub|pw|pwc|py|qpon|quebec|quest|qvc|radio|raid|re|read|realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|restaurant|review|reviews|rexroth|rich|richardli|ricoh|rightathome|ril|rio|rip|rmit|ro|rocher|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|sandvikcoromant|sanofi|sap|sapo|sarl|sas|save|saxo|sb|sbi|sbs|sc|sca|scb|schaeffler|schmidt|scholarships|school|schule|schwarz|science|scjohnson|scor|scot|sd|se|search|seat|secure|security|seek|select|sener|services|ses|seven|sew|sex|sexy|sfr|sg|sh|shangrila|sharp|shaw|shell|shia|shiksha|shoes|shop|shopping|shouji|show|showtime|shriram|si|silk|sina|singles|site|sj|sk|ski|skin|sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|software|sohu|solar|solutions|song|sony|soy|space|spiegel|sport|spot|spreadbetting|sr|srl|srt|ss|st|stada|staples|star|starhub|statebank|statefarm|statoil|stc|stcgroup|stockholm|storage|store|stream|studio|study|style|su|sucks|supplies|supply|support|surf|surgery|suzuki|sv|swatch|swiftcover|swiss|sx|sy|sydney|symantec|systems|sz|taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|tdk|team|tech|technology|tel|telecity|telefonica|temasek|tennis|teva|tf|tg|th|thd|theater|theatre|tiaa|tickets|tienda|tiffany|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|toyota|toys|tp|tr|trade|trading|training|travel|travelchannel|travelers|travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ubank|ubs|uconnect|ug|uk|um|unicom|university|uno|uol|ups|us|uy|uz|vacations|vana|vanguard|vc|ve|vegas|ventures|verisign|vermögensberater|vermögensberatung|versicherung|vet|vg|vi|viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|vista|vistaprint|viva|vivo|vlaanderen|vn|vodka|volkswagen|volvo|vote|voting|voto|voyage|vu|vuelos|walmart|walter|wang|wanggou|warman|watch|watches|weather|weatherchannel|webcam|weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|wow|ws|wtc|wtf|xerox|xfinity|xihuan|xin|xperia|xxx|xyz|yahoo|yamaxun|yandex|ye|yodobashi|yoga|yokohama|you|youtube|yt|yun|zappos|zara|zero|zip|zippo|zm|zone|zuerich|zw)'
        # urls = re.findall(r'''(http[s]?://([a-z0-9\-]{1,64}\.)+%s.*?)[\s:;\(\)\{\}<>~\^'"]'''%(domain_suf), response)
        urls = re.findall(
            r'''(http[s]?://([a-z0-9\-]{1,64}\.)+%s.*?)[\\\s:$;,%s\(\)\{\}<>~\^'"]''' % (domain_suf, "%"), response)
        links += [url[0] for url in urls]
        datas = [self.format_url(x) for x in list(set(links))]
        return datas

    def process_url(self, URL, re_URL):
        black_url = ["javascript:"]  # Add some keyword for filter url.
        URL_raw = urlparse(URL)
        ab_URL = URL_raw.netloc
        host_URL = URL_raw.scheme
        if re_URL[0:2] == "//":
            result = host_URL + ":" + re_URL
        elif re_URL[0:4] == "http":
            result = re_URL
        elif re_URL[0:2] != "//" and re_URL.lower() not in black_url:
            if re_URL[0:1] == "/":
                result = host_URL + "://" + ab_URL + re_URL
            else:
                if re_URL[0:1] == ".":
                    if re_URL[0:2] == "..":
                        result = host_URL + "://" + ab_URL + re_URL[2:]
                    else:
                        result = host_URL + "://" + ab_URL + re_URL[1:]
                else:
                    result = host_URL + "://" + ab_URL + "/" + re_URL
        else:
            result = URL
        return result

    def getallargs(self, dictdata):
        tmp = []
        tmp_value = []
        params_body = dictdata.get("request").get("params").get("params_body")
        params_url = dictdata.get("request").get("params").get("params_url")
        params_cookie = dictdata.get("request").get("params").get("params_cookie")
        if params_body:
            for param in params_body:
                tmp.append(param.get("name") + "frombody")
                tmp_value.append(param.get("value", "") + "frombody")
        if params_url:
            for param in params_url:
                tmp.append(param.get("name") + "fromurl")
                tmp_value.append(param.get("value", "") + "fromurl")

        # if params_cookie:
        #     for param in params_cookie:
        #         tmp.append(param.get("name") + "fromcookie")
        # tmp_value.append(param.get("value", "") + "fromcookie")
        return sorted(list(set(tmp))), sorted(list(set(tmp_value)))

    def http_md5(self, dictdata):
        '''
        return bool
        '''
        method = dictdata.get("request").get("method")
        name, value = self.getallargs(dictdata)
        if db_set.get("es_uniq"):
            hashstr = getmd5(
                "{protocol}-{host}-{port}-{method}-{path}-{argsname}".format(argsname="".join(name),
                                                                             method=method,
                                                                             **dictdata.get("url")))

        else:
            hashstr = getmd5(
                "{protocol}-{host}-{port}-{method}-{path}-{argsname}-{value}".format(
                    argsname="".join(name), value="".join(value),
                    method=method,
                    **dictdata.get("url")))
        return hashstr
