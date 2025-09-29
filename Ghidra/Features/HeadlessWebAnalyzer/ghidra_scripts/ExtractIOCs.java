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
//Extract Indicators of Compromise (IOCs) from the current program
//@category MalwareAnalysis
//@keybinding
//@menupath Analysis.Malware.Extract IOCs
//@toolbar

import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

public class ExtractIOCs extends GhidraScript {

    private static final Pattern IP_PATTERN = Pattern.compile(
        "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
    
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "\\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}\\b");
    
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[a-zA-Z0-9.-]+(?:/[^\\s]*)?");
    
    private static final Pattern REGISTRY_PATTERN = Pattern.compile(
        "(?i)(?:HKEY_|HKLM\\\\|HKCU\\\\|HKCR\\\\|HKU\\\\)[^\\x00\\n\\r]+");
    
    private static final Pattern MUTEX_PATTERN = Pattern.compile(
        "(?i)(?:Global\\\\|Local\\\\)?[a-zA-Z0-9_\\-]{4,}(?:Mutex|Event|Semaphore)?");

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("No program loaded");
            return;
        }

        println("=== IOC Extraction Results ===");
        println("Program: " + currentProgram.getName());
        println();

        Set<String> ipAddresses = new HashSet<>();
        Set<String> domains = new HashSet<>();
        Set<String> urls = new HashSet<>();
        Set<String> registryKeys = new HashSet<>();
        Set<String> mutexes = new HashSet<>();

        // Extract from strings
        extractFromStrings(ipAddresses, domains, urls, registryKeys, mutexes);

        // Extract from memory
        extractFromMemory(ipAddresses, domains, urls, registryKeys, mutexes);

        // Print results
        printIOCs("IP Addresses", ipAddresses);
        printIOCs("Domains", domains);
        printIOCs("URLs", urls);
        printIOCs("Registry Keys", registryKeys);
        printIOCs("Mutexes/Objects", mutexes);

        println("\n=== IOC Extraction Complete ===");
    }

    private void extractFromStrings(Set<String> ipAddresses, Set<String> domains, 
                                  Set<String> urls, Set<String> registryKeys, Set<String> mutexes) {
        
        println("Extracting IOCs from defined strings...");
        
        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        
        while (dataIterator.hasNext() && !monitor.isCancelled()) {
            Data data = dataIterator.next();
            
            if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();
                if (stringValue != null && stringValue.length() > 3) {
                    extractIOCsFromString(stringValue, ipAddresses, domains, urls, registryKeys, mutexes);
                }
            }
        }
    }

    private void extractFromMemory(Set<String> ipAddresses, Set<String> domains, 
                                 Set<String> urls, Set<String> registryKeys, Set<String> mutexes) {
        
        println("Extracting IOCs from memory blocks...");
        
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        
        for (MemoryBlock block : blocks) {
            if (monitor.isCancelled()) break;
            
            if (block.isInitialized() && block.isRead()) {
                try {
                    byte[] bytes = new byte[(int) block.getSize()];
                    block.getBytes(block.getStart(), bytes);
                    
                    // Convert to string and extract IOCs
                    String content = new String(bytes, "ISO-8859-1");
                    extractIOCsFromString(content, ipAddresses, domains, urls, registryKeys, mutexes);
                    
                } catch (Exception e) {
                    println("Error processing block " + block.getName() + ": " + e.getMessage());
                }
            }
        }
    }

    private void extractIOCsFromString(String text, Set<String> ipAddresses, Set<String> domains, 
                                     Set<String> urls, Set<String> registryKeys, Set<String> mutexes) {
        
        // Extract IP addresses
        Matcher ipMatcher = IP_PATTERN.matcher(text);
        while (ipMatcher.find()) {
            String ip = ipMatcher.group();
            if (isValidIP(ip)) {
                ipAddresses.add(ip);
            }
        }

        // Extract URLs (do this before domains to avoid duplicates)
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        while (urlMatcher.find()) {
            urls.add(urlMatcher.group());
        }

        // Extract domains (excluding those already in URLs)
        Matcher domainMatcher = DOMAIN_PATTERN.matcher(text);
        while (domainMatcher.find()) {
            String domain = domainMatcher.group();
            if (isInterestingDomain(domain)) {
                domains.add(domain);
            }
        }

        // Extract registry keys
        Matcher registryMatcher = REGISTRY_PATTERN.matcher(text);
        while (registryMatcher.find()) {
            registryKeys.add(registryMatcher.group());
        }

        // Extract mutex-like strings
        Matcher mutexMatcher = MUTEX_PATTERN.matcher(text);
        while (mutexMatcher.find()) {
            String mutex = mutexMatcher.group();
            if (isInterestingMutex(mutex)) {
                mutexes.add(mutex);
            }
        }
    }

    private boolean isValidIP(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        
        for (String part : parts) {
            try {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        // Exclude common non-routable IPs
        return !ip.startsWith("0.") && !ip.startsWith("127.") && 
               !ip.equals("255.255.255.255") && !ip.equals("0.0.0.0");
    }

    private boolean isInterestingDomain(String domain) {
        domain = domain.toLowerCase();
        
        // Exclude common legitimate domains
        String[] commonDomains = {
            "microsoft.com", "google.com", "windows.com", "apple.com",
            "localhost", "example.com", "test.com"
        };
        
        for (String common : commonDomains) {
            if (domain.contains(common)) {
                return false;
            }
        }
        
        // Must have valid TLD and be reasonable length
        return domain.length() > 4 && domain.contains(".") && 
               !domain.endsWith(".dll") && !domain.endsWith(".exe");
    }

    private boolean isInterestingMutex(String mutex) {
        mutex = mutex.toLowerCase();
        
        // Exclude very common system mutexes
        return !mutex.contains("system") && !mutex.contains("windows") && 
               !mutex.contains("microsoft") && mutex.length() > 3;
    }

    private void printIOCs(String category, Set<String> iocs) {
        if (!iocs.isEmpty()) {
            println("\n" + category + " (" + iocs.size() + "):");
            println("=" + "=".repeat(category.length() + 10));
            
            for (String ioc : iocs) {
                println("  " + ioc);
            }
        }
    }
}