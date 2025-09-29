/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.features.headlessweb.model;

import java.util.List;

/**
 * Indicators of Compromise extracted from malware analysis
 */
public class IOCResult {
    private List<String> ipAddresses;
    private List<String> domains;
    private List<String> urls;
    private List<String> fileHashes;
    private List<String> registryKeys;
    private List<String> mutexes;
    private List<String> filePaths;
    private List<String> networkPorts;
    private List<String> userAgents;
    private List<String> cryptoKeys;
    
    public IOCResult() {}
    
    // Getters and Setters
    public List<String> getIpAddresses() { return ipAddresses; }
    public void setIpAddresses(List<String> ipAddresses) { this.ipAddresses = ipAddresses; }
    
    public List<String> getDomains() { return domains; }
    public void setDomains(List<String> domains) { this.domains = domains; }
    
    public List<String> getUrls() { return urls; }
    public void setUrls(List<String> urls) { this.urls = urls; }
    
    public List<String> getFileHashes() { return fileHashes; }
    public void setFileHashes(List<String> fileHashes) { this.fileHashes = fileHashes; }
    
    public List<String> getRegistryKeys() { return registryKeys; }
    public void setRegistryKeys(List<String> registryKeys) { this.registryKeys = registryKeys; }
    
    public List<String> getMutexes() { return mutexes; }
    public void setMutexes(List<String> mutexes) { this.mutexes = mutexes; }
    
    public List<String> getFilePaths() { return filePaths; }
    public void setFilePaths(List<String> filePaths) { this.filePaths = filePaths; }
    
    public List<String> getNetworkPorts() { return networkPorts; }
    public void setNetworkPorts(List<String> networkPorts) { this.networkPorts = networkPorts; }
    
    public List<String> getUserAgents() { return userAgents; }
    public void setUserAgents(List<String> userAgents) { this.userAgents = userAgents; }
    
    public List<String> getCryptoKeys() { return cryptoKeys; }
    public void setCryptoKeys(List<String> cryptoKeys) { this.cryptoKeys = cryptoKeys; }
}