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
 * Configuration options for analysis operations
 */
public class AnalysisOptions {
    private boolean analysisEnabled = true;
    private boolean extractStrings = true;
    private boolean extractFunctions = true;
    private boolean extractIOCs = true;
    private boolean performDeobfuscation = false;
    private boolean useML = false;
    private List<String> preScripts;
    private List<String> postScripts;
    private String processor;
    private String compilerSpec;
    private int timeoutSeconds = 3600; // 1 hour default
    
    // Constructors
    public AnalysisOptions() {}
    
    // Getters and Setters
    public boolean isAnalysisEnabled() { return analysisEnabled; }
    public void setAnalysisEnabled(boolean analysisEnabled) { this.analysisEnabled = analysisEnabled; }
    
    public boolean isExtractStrings() { return extractStrings; }
    public void setExtractStrings(boolean extractStrings) { this.extractStrings = extractStrings; }
    
    public boolean isExtractFunctions() { return extractFunctions; }
    public void setExtractFunctions(boolean extractFunctions) { this.extractFunctions = extractFunctions; }
    
    public boolean isExtractIOCs() { return extractIOCs; }
    public void setExtractIOCs(boolean extractIOCs) { this.extractIOCs = extractIOCs; }
    
    public boolean isPerformDeobfuscation() { return performDeobfuscation; }
    public void setPerformDeobfuscation(boolean performDeobfuscation) { this.performDeobfuscation = performDeobfuscation; }
    
    public boolean isUseML() { return useML; }
    public void setUseML(boolean useML) { this.useML = useML; }
    
    public List<String> getPreScripts() { return preScripts; }
    public void setPreScripts(List<String> preScripts) { this.preScripts = preScripts; }
    
    public List<String> getPostScripts() { return postScripts; }
    public void setPostScripts(List<String> postScripts) { this.postScripts = postScripts; }
    
    public String getProcessor() { return processor; }
    public void setProcessor(String processor) { this.processor = processor; }
    
    public String getCompilerSpec() { return compilerSpec; }
    public void setCompilerSpec(String compilerSpec) { this.compilerSpec = compilerSpec; }
    
    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
}