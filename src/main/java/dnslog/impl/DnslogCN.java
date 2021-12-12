package dnslog.impl;

import dnslog.IDnslog;
import utils.MyHttpClient;

import java.io.IOException;
import java.util.Map;

public class DnslogCN implements IDnslog {
    private String url = "http://www.dnslog.cn/";
    private MyHttpClient myHttpClient = new MyHttpClient();
    @Override
    public String getNewDomain() throws IOException {
        String newDomain = url + "getdomain.php";
        Map<String, String> map = this.myHttpClient.doGet_forCookieAndHost(newDomain);
        return map.get("content");

    }

    @Override
    public boolean getState(String key) throws IOException {
        String recordDomain = url + "getrecords.php";
        String result = this.myHttpClient.doGet_forState(recordDomain, this.myHttpClient.GLOGAL_COOKIE.get(key));
        if (result.length() > 3){
            return true;
        }
        return false;
    }
}
