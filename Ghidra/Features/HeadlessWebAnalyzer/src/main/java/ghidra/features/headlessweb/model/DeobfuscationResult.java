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
 * Results from ML-powered deobfuscation analysis
 */
public class DeobfuscationResult {
    private boolean isObfuscated;
    private String obfuscationType;
    private List<String> deobfuscatedStrings;
    private List<String> recoveredFunctionNames;
    private String deobfuscationMethod;
    private double successRate;
    private String originalCode;
    private String deobfuscatedCode;
    
    public DeobfuscationResult() {}
    
    // Getters and Setters
    public boolean isObfuscated() { return isObfuscated; }
    public void setObfuscated(boolean obfuscated) { isObfuscated = obfuscated; }
    
    public String getObfuscationType() { return obfuscationType; }
    public void setObfuscationType(String obfuscationType) { this.obfuscationType = obfuscationType; }
    
    public List<String> getDeobfuscatedStrings() { return deobfuscatedStrings; }
    public void setDeobfuscatedStrings(List<String> deobfuscatedStrings) { this.deobfuscatedStrings = deobfuscatedStrings; }
    
    public List<String> getRecoveredFunctionNames() { return recoveredFunctionNames; }
    public void setRecoveredFunctionNames(List<String> recoveredFunctionNames) { this.recoveredFunctionNames = recoveredFunctionNames; }
    
    public String getDeobfuscationMethod() { return deobfuscationMethod; }
    public void setDeobfuscationMethod(String deobfuscationMethod) { this.deobfuscationMethod = deobfuscationMethod; }
    
    public double getSuccessRate() { return successRate; }
    public void setSuccessRate(double successRate) { this.successRate = successRate; }
    
    public String getOriginalCode() { return originalCode; }
    public void setOriginalCode(String originalCode) { this.originalCode = originalCode; }
    
    public String getDeobfuscatedCode() { return deobfuscatedCode; }
    public void setDeobfuscatedCode(String deobfuscatedCode) { this.deobfuscatedCode = deobfuscatedCode; }
}