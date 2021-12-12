package utils;
import org.apache.http.HttpEntity;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MyHttpClient {
    public Map<String,List<Cookie>> GLOGAL_COOKIE = new HashMap<String,List<Cookie>>();

    public Map<String,String> doGet_forCookieAndHost(String http_url) throws IOException {
        Map<String,String> map = new HashMap<String,String>();
        String result = null;
        CloseableHttpClient httpClient = null;
        CloseableHttpResponse httpResponse = null;
        CookieStore cookieStore = null;
        cookieStore = new BasicCookieStore();
        httpClient = HttpClients.custom().setDefaultCookieStore(cookieStore).build();
        HttpGet httpGet = new HttpGet(http_url);
        httpGet.setHeader("User-Agent","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36");
        // 设置配置请求参数
        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(35000)// 连接主机服务超时时间
                .setConnectionRequestTimeout(35000)// 请求超时时间
                .setSocketTimeout(60000)// 数据读取超时时间
                .build();
        httpGet.setConfig(requestConfig);

        httpResponse = httpClient.execute(httpGet);
        // 从响应对象中获取响应内容
        HttpEntity entity = httpResponse.getEntity();
        result = EntityUtils.toString(entity);
        List<Cookie> cookies = cookieStore.getCookies();
        map.put("content",result);
        GLOGAL_COOKIE.put(result,cookies);
        httpClient.close();
        return map;
    }



    public String doGet_forState(String http_url,List<Cookie> cookieList) throws IOException {
        String result = null;
        CloseableHttpClient httpClient = null;
        CloseableHttpResponse httpResponse = null;
        CookieStore cookieStore = new BasicCookieStore();
        for (Cookie cOokie:cookieList){
            cookieStore.addCookie(cOokie);
        }
        httpClient = HttpClients.custom().setDefaultCookieStore(cookieStore).build();
        HttpGet httpGet = new HttpGet(http_url);
        httpGet.setHeader("User-Agent","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36");
        // 设置配置请求参数
        RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(35000)// 连接主机服务超时时间
                .setConnectionRequestTimeout(35000)// 请求超时时间
                .setSocketTimeout(60000)// 数据读取超时时间
                .build();
        httpGet.setConfig(requestConfig);

        httpResponse = httpClient.execute(httpGet);
        // 从响应对象中获取响应内容
        HttpEntity entity = httpResponse.getEntity();
        result = EntityUtils.toString(entity);
        httpClient.close();
        return result;
    }

}