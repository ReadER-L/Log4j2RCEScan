package dnslog;

import java.io.IOException;

public interface IDnslog {
    String getNewDomain() throws IOException;
    boolean getState(String key) throws IOException;
}
