
import dnslog.IDnslog;
import dnslog.impl.DnslogCN;
import org.apache.http.cookie.Cookie;
import utils.MyHttpClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class httptest {
    public static void main(String[] args) throws IOException {
        //MyHttpClient myHttpClient = new MyHttpClient();

        IDnslog iDnslog = new DnslogCN();
        String newDomain = iDnslog.getNewDomain();
        iDnslog.getState(newDomain);
////        Map<String, String> map = myHttpClient.doGet_forCookieAndHost("http://www.dnslog.cn/getdomain.php");
//        String result = map.get("content");
//        String map1 = myHttpClient.doGet_forState("http://www.dnslog.cn/getrecords.php", myHttpClient.cookie_map.get(result));
//        System.out.println(map1);

    }
}
